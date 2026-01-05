package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	logging "cloud.google.com/go/logging/apiv2"
	"cloud.google.com/go/logging/apiv2/loggingpb"
	"google.golang.org/api/iterator"
	"google.golang.org/protobuf/encoding/protojson"
)

// GCPCloudLoggingSource reads Kubernetes audit logs from GCP Cloud Logging.
// GKE clusters write audit logs to projects/<project>/logs/cloudaudit.googleapis.com%2Factivity
// and projects/<project>/logs/externalaudit.googleapis.com%2Factivity for admin activity.
type GCPCloudLoggingSource struct {
	client    *logging.Client
	projectID string
	cluster   string
	location  string
}

// GCPCloudLoggingConfig holds configuration for GCP Cloud Logging source
type GCPCloudLoggingConfig struct {
	ProjectID string // GCP project ID
	Cluster   string // GKE cluster name (optional, filters to specific cluster)
	Location  string // GKE cluster location (optional)
}

// NewGCPCloudLoggingSource creates a new GCP Cloud Logging audit source
func NewGCPCloudLoggingSource(ctx context.Context, cfg GCPCloudLoggingConfig) (*GCPCloudLoggingSource, error) {
	client, err := logging.NewClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create Cloud Logging client: %w", err)
	}

	return &GCPCloudLoggingSource{
		client:    client,
		projectID: cfg.ProjectID,
		cluster:   cfg.Cluster,
		location:  cfg.Location,
	}, nil
}

func (g *GCPCloudLoggingSource) Name() string {
	return "gcp-cloud-logging"
}

func (g *GCPCloudLoggingSource) GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error) {
	filter := g.buildFilter(opts)

	req := &loggingpb.ListLogEntriesRequest{
		ResourceNames: []string{fmt.Sprintf("projects/%s", g.projectID)},
		Filter:        filter,
		OrderBy:       "timestamp desc",
		PageSize:      1000,
	}

	if opts.Limit > 0 && opts.Limit < 1000 {
		req.PageSize = int32(opts.Limit)
	}

	var events []Event
	it := g.client.ListLogEntries(ctx, req)

	for {
		entry, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return events, fmt.Errorf("failed to read log entries: %w", err)
		}

		event, err := g.parseLogEntry(entry)
		if err != nil {
			continue
		}

		if matchesQuery(event, opts) {
			events = append(events, event)
		}

		if opts.Limit > 0 && len(events) >= opts.Limit {
			break
		}
	}

	return events, nil
}

func (g *GCPCloudLoggingSource) buildFilter(opts QueryOptions) string {
	// GKE audit logs are in the data_access and activity logs
	filter := `resource.type="k8s_cluster" AND
		(logName:"cloudaudit.googleapis.com%2Factivity" OR
		 logName:"cloudaudit.googleapis.com%2Fdata_access" OR
		 logName:"externalaudit.googleapis.com%2Factivity")`

	// Filter by cluster name
	if g.cluster != "" {
		filter += fmt.Sprintf(` AND resource.labels.cluster_name="%s"`, g.cluster)
	}

	// Filter by location
	if g.location != "" {
		filter += fmt.Sprintf(` AND resource.labels.location="%s"`, g.location)
	}

	// Time range
	if !opts.StartTime.IsZero() {
		filter += fmt.Sprintf(` AND timestamp>="%s"`, opts.StartTime.Format(time.RFC3339))
	}
	if !opts.EndTime.IsZero() {
		filter += fmt.Sprintf(` AND timestamp<="%s"`, opts.EndTime.Format(time.RFC3339))
	}

	// Filter by namespace (if supported in the log structure)
	if opts.Namespace != "" {
		filter += fmt.Sprintf(` AND protoPayload.resourceName:"%s"`, opts.Namespace)
	}

	// Filter by user
	if opts.User != "" {
		filter += fmt.Sprintf(` AND protoPayload.authenticationInfo.principalEmail="%s"`, opts.User)
	}

	// Filter by verb/method
	if opts.Verb != "" {
		filter += fmt.Sprintf(` AND protoPayload.methodName:"%s"`, opts.Verb)
	}

	return filter
}

func (g *GCPCloudLoggingSource) parseLogEntry(entry *loggingpb.LogEntry) (Event, error) {
	timestamp := entry.GetTimestamp().AsTime()

	// Parse the protoPayload which contains the audit info
	var payload map[string]interface{}
	if jsonPayload := entry.GetJsonPayload(); jsonPayload != nil {
		payload = jsonPayload.AsMap()
	} else if protoPayload := entry.GetProtoPayload(); protoPayload != nil {
		// Unmarshal proto payload
		payloadBytes, err := protojson.Marshal(protoPayload)
		if err == nil {
			json.Unmarshal(payloadBytes, &payload)
		}
	}

	event := Event{
		Timestamp: timestamp,
		AuditID:   entry.GetInsertId(),
	}

	if payload != nil {
		// Extract authentication info
		if authInfo, ok := payload["authenticationInfo"].(map[string]interface{}); ok {
			if principal, ok := authInfo["principalEmail"].(string); ok {
				event.User.Username = principal
			}
		}

		// Extract method name as verb
		if method, ok := payload["methodName"].(string); ok {
			event.Verb = method
		}

		// Extract resource info
		if resourceName, ok := payload["resourceName"].(string); ok {
			event.ObjectRef.Name = resourceName
		}

		// Extract request metadata
		if requestMeta, ok := payload["requestMetadata"].(map[string]interface{}); ok {
			if callerIP, ok := requestMeta["callerIp"].(string); ok {
				event.SourceIPs = []string{callerIP}
			}
		}

		// Extract status
		if status, ok := payload["status"].(map[string]interface{}); ok {
			if code, ok := status["code"].(float64); ok {
				event.ResponseStatus.Code = int(code)
			}
			if message, ok := status["message"].(string); ok {
				event.ResponseStatus.Message = message
			}
		}

		// Try to extract Kubernetes-specific info from request/response
		if request, ok := payload["request"].(map[string]interface{}); ok {
			if ns, ok := request["namespace"].(string); ok {
				event.ObjectRef.Namespace = ns
			}
			if resource, ok := request["resource"].(string); ok {
				event.ObjectRef.Resource = resource
			}
		}
	}

	// Parse Kubernetes labels from resource
	if labels := entry.GetResource().GetLabels(); labels != nil {
		if ns, ok := labels["namespace_name"]; ok {
			event.ObjectRef.Namespace = ns
		}
	}

	return event, nil
}

func (g *GCPCloudLoggingSource) StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error) {
	ch := make(chan Event, 100)

	go func() {
		defer close(ch)

		// For streaming, poll periodically
		ticker := time.NewTicker(10 * time.Second)
		defer ticker.Stop()

		lastTime := opts.StartTime
		if lastTime.IsZero() {
			lastTime = time.Now().Add(-1 * time.Minute)
		}

		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				queryOpts := opts
				queryOpts.StartTime = lastTime
				queryOpts.EndTime = time.Now()

				events, err := g.GetEvents(ctx, queryOpts)
				if err != nil {
					continue
				}

				for _, event := range events {
					select {
					case ch <- event:
						if event.Timestamp.After(lastTime) {
							lastTime = event.Timestamp
						}
					case <-ctx.Done():
						return
					}
				}
			}
		}
	}()

	return ch, nil
}

func (g *GCPCloudLoggingSource) Close() error {
	if g.client != nil {
		return g.client.Close()
	}
	return nil
}

// GKEAdminActivitySource specifically queries GKE admin activity logs
type GKEAdminActivitySource struct {
	*GCPCloudLoggingSource
}

// NewGKEAdminActivitySource creates a source for GKE admin activity audit logs
func NewGKEAdminActivitySource(ctx context.Context, cfg GCPCloudLoggingConfig) (*GKEAdminActivitySource, error) {
	base, err := NewGCPCloudLoggingSource(ctx, cfg)
	if err != nil {
		return nil, err
	}
	return &GKEAdminActivitySource{base}, nil
}

func (g *GKEAdminActivitySource) Name() string {
	return "gke-admin-activity"
}

// GetTopPrincipals returns the top principals by request count
func (g *GCPCloudLoggingSource) GetTopPrincipals(ctx context.Context, since time.Duration, limit int) ([]map[string]interface{}, error) {
	filter := g.buildFilter(QueryOptions{
		StartTime: time.Now().Add(-since),
		EndTime:   time.Now(),
	})

	req := &loggingpb.ListLogEntriesRequest{
		ResourceNames: []string{fmt.Sprintf("projects/%s", g.projectID)},
		Filter:        filter,
		OrderBy:       "timestamp desc",
		PageSize:      1000,
	}

	principals := make(map[string]int)
	it := g.client.ListLogEntries(ctx, req)

	for {
		entry, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}

		// Extract principal from protoPayload
		if protoPayload := entry.GetProtoPayload(); protoPayload != nil {
			payloadBytes, err := protojson.Marshal(protoPayload)
			if err == nil {
				var payload map[string]interface{}
				if json.Unmarshal(payloadBytes, &payload) == nil {
					if authInfo, ok := payload["authenticationInfo"].(map[string]interface{}); ok {
						if principal, ok := authInfo["principalEmail"].(string); ok {
							principals[principal]++
						}
					}
				}
			}
		}
	}

	// Convert to sorted result
	var result []map[string]interface{}
	for principal, count := range principals {
		result = append(result, map[string]interface{}{
			"principal": principal,
			"count":     count,
		})
	}

	// Simple sort by count descending
	for i := 0; i < len(result)-1; i++ {
		for j := i + 1; j < len(result); j++ {
			if result[j]["count"].(int) > result[i]["count"].(int) {
				result[i], result[j] = result[j], result[i]
			}
		}
	}

	if limit > 0 && len(result) > limit {
		result = result[:limit]
	}

	return result, nil
}
