package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"time"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs"
	"github.com/aws/aws-sdk-go-v2/service/cloudwatchlogs/types"
)

// CloudWatchSource reads Kubernetes audit logs from AWS CloudWatch Logs.
// EKS clusters write audit logs to /aws/eks/<cluster-name>/cluster log group.
type CloudWatchSource struct {
	client       *cloudwatchlogs.Client
	logGroup     string
	region       string
	filterPrefix string
}

// CloudWatchConfig holds configuration for CloudWatch source
type CloudWatchConfig struct {
	LogGroup     string // e.g., /aws/eks/my-cluster/cluster
	Region       string // AWS region
	FilterPrefix string // Optional: filter log streams (e.g., "kube-apiserver-audit")
}

// NewCloudWatchSource creates a new CloudWatch Logs audit source
func NewCloudWatchSource(ctx context.Context, cfg CloudWatchConfig) (*CloudWatchSource, error) {
	awsCfg, err := config.LoadDefaultConfig(ctx,
		config.WithRegion(cfg.Region),
	)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	client := cloudwatchlogs.NewFromConfig(awsCfg)

	// Verify log group exists
	_, err = client.DescribeLogGroups(ctx, &cloudwatchlogs.DescribeLogGroupsInput{
		LogGroupNamePrefix: aws.String(cfg.LogGroup),
		Limit:              aws.Int32(1),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to access log group %s: %w", cfg.LogGroup, err)
	}

	return &CloudWatchSource{
		client:       client,
		logGroup:     cfg.LogGroup,
		region:       cfg.Region,
		filterPrefix: cfg.FilterPrefix,
	}, nil
}

func (c *CloudWatchSource) Name() string {
	return "cloudwatch"
}

func (c *CloudWatchSource) GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error) {
	var allEvents []Event

	// Build filter pattern for CloudWatch Logs Insights
	filterPattern := c.buildFilterPattern(opts)

	// Get log streams (EKS uses kube-apiserver-audit-* streams)
	streams, err := c.getLogStreams(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to get log streams: %w", err)
	}

	if len(streams) == 0 {
		return nil, fmt.Errorf("no audit log streams found in %s", c.logGroup)
	}

	// Query each stream
	for _, stream := range streams {
		events, err := c.queryLogStream(ctx, stream, opts, filterPattern)
		if err != nil {
			// Log error but continue with other streams
			continue
		}
		allEvents = append(allEvents, events...)

		// Check limit
		if opts.Limit > 0 && len(allEvents) >= opts.Limit {
			allEvents = allEvents[:opts.Limit]
			break
		}
	}

	return allEvents, nil
}

func (c *CloudWatchSource) getLogStreams(ctx context.Context) ([]string, error) {
	var streams []string

	input := &cloudwatchlogs.DescribeLogStreamsInput{
		LogGroupName: aws.String(c.logGroup),
		Limit:        aws.Int32(50), // Get recent streams
	}

	// Note: Cannot use OrderBy with LogStreamNamePrefix per AWS API limitation
	if c.filterPrefix != "" {
		input.LogStreamNamePrefix = aws.String(c.filterPrefix)
	} else {
		// Default: look for audit streams
		input.LogStreamNamePrefix = aws.String("kube-apiserver-audit")
	}

	paginator := cloudwatchlogs.NewDescribeLogStreamsPaginator(c.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, stream := range page.LogStreams {
			if stream.LogStreamName != nil {
				streams = append(streams, *stream.LogStreamName)
			}
		}

		// Limit to reasonable number of streams
		if len(streams) >= 50 {
			break
		}
	}

	return streams, nil
}

func (c *CloudWatchSource) queryLogStream(ctx context.Context, streamName string, opts QueryOptions, filterPattern string) ([]Event, error) {
	var events []Event

	startTime := opts.StartTime.UnixMilli()
	endTime := opts.EndTime.UnixMilli()
	if endTime == 0 {
		endTime = time.Now().UnixMilli()
	}

	input := &cloudwatchlogs.FilterLogEventsInput{
		LogGroupName:   aws.String(c.logGroup),
		LogStreamNames: []string{streamName},
		StartTime:      aws.Int64(startTime),
		EndTime:        aws.Int64(endTime),
	}

	if filterPattern != "" {
		input.FilterPattern = aws.String(filterPattern)
	}

	if opts.Limit > 0 {
		input.Limit = aws.Int32(int32(opts.Limit))
	}

	paginator := cloudwatchlogs.NewFilterLogEventsPaginator(c.client, input)

	for paginator.HasMorePages() {
		page, err := paginator.NextPage(ctx)
		if err != nil {
			return events, err
		}

		for _, logEvent := range page.Events {
			if logEvent.Message == nil {
				continue
			}

			event, err := parseAuditEvent(*logEvent.Message)
			if err != nil {
				continue
			}

			if matchesQuery(event, opts) {
				events = append(events, event)
			}

			if opts.Limit > 0 && len(events) >= opts.Limit {
				return events, nil
			}
		}
	}

	return events, nil
}

func (c *CloudWatchSource) buildFilterPattern(opts QueryOptions) string {
	// CloudWatch filter pattern syntax
	// https://docs.aws.amazon.com/AmazonCloudWatch/latest/logs/FilterAndPatternSyntax.html

	var patterns []string

	if opts.Namespace != "" {
		patterns = append(patterns, fmt.Sprintf(`{ $.objectRef.namespace = "%s" }`, opts.Namespace))
	}

	if opts.User != "" {
		patterns = append(patterns, fmt.Sprintf(`{ $.user.username = "%s" }`, opts.User))
	}

	if opts.Resource != "" {
		patterns = append(patterns, fmt.Sprintf(`{ $.objectRef.resource = "%s" }`, opts.Resource))
	}

	if opts.Verb != "" {
		patterns = append(patterns, fmt.Sprintf(`{ $.verb = "%s" }`, opts.Verb))
	}

	// Combine patterns - CloudWatch doesn't support complex AND directly,
	// so we'll filter further in code
	if len(patterns) == 1 {
		return patterns[0]
	}

	return ""
}

func (c *CloudWatchSource) StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error) {
	ch := make(chan Event, 100)

	go func() {
		defer close(ch)

		// For streaming, we poll periodically
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

				events, err := c.GetEvents(ctx, queryOpts)
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

func (c *CloudWatchSource) Close() error {
	return nil
}

// GetEKSLogGroup returns the standard EKS audit log group name for a cluster
func GetEKSLogGroup(clusterName string) string {
	return fmt.Sprintf("/aws/eks/%s/cluster", clusterName)
}

// CloudWatchInsightsQuery runs a CloudWatch Logs Insights query for more complex analysis
func (c *CloudWatchSource) RunInsightsQuery(ctx context.Context, query string, startTime, endTime time.Time) ([]map[string]string, error) {
	input := &cloudwatchlogs.StartQueryInput{
		LogGroupName: aws.String(c.logGroup),
		StartTime:    aws.Int64(startTime.Unix()),
		EndTime:      aws.Int64(endTime.Unix()),
		QueryString:  aws.String(query),
	}

	startResult, err := c.client.StartQuery(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("failed to start query: %w", err)
	}

	// Poll for results
	for {
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-time.After(1 * time.Second):
		}

		resultInput := &cloudwatchlogs.GetQueryResultsInput{
			QueryId: startResult.QueryId,
		}

		result, err := c.client.GetQueryResults(ctx, resultInput)
		if err != nil {
			return nil, fmt.Errorf("failed to get query results: %w", err)
		}

		if result.Status == types.QueryStatusComplete {
			return c.parseInsightsResults(result.Results), nil
		}

		if result.Status == types.QueryStatusFailed || result.Status == types.QueryStatusCancelled {
			return nil, fmt.Errorf("query %s: %s", result.Status, *startResult.QueryId)
		}
	}
}

func (c *CloudWatchSource) parseInsightsResults(results [][]types.ResultField) []map[string]string {
	var parsed []map[string]string

	for _, row := range results {
		record := make(map[string]string)
		for _, field := range row {
			if field.Field != nil && field.Value != nil {
				record[*field.Field] = *field.Value
			}
		}
		parsed = append(parsed, record)
	}

	return parsed
}

// GetTopUsers returns the top users by request count using CloudWatch Insights
func (c *CloudWatchSource) GetTopUsers(ctx context.Context, since time.Duration, limit int) ([]map[string]string, error) {
	query := fmt.Sprintf(`
		fields @timestamp, user.username, verb, objectRef.resource
		| filter @logStream like /kube-apiserver-audit/
		| stats count(*) as requestCount by user.username
		| sort requestCount desc
		| limit %d
	`, limit)

	return c.RunInsightsQuery(ctx, query, time.Now().Add(-since), time.Now())
}

// GetUnusedServiceAccounts finds service accounts that haven't made requests
func (c *CloudWatchSource) GetUnusedServiceAccounts(ctx context.Context, since time.Duration) ([]map[string]string, error) {
	query := `
		fields @timestamp, user.username, verb, objectRef.resource
		| filter @logStream like /kube-apiserver-audit/
		| filter user.username like /system:serviceaccount:/
		| stats count(*) as requestCount, max(@timestamp) as lastSeen by user.username
		| sort requestCount asc
		| limit 100
	`

	return c.RunInsightsQuery(ctx, query, time.Now().Add(-since), time.Now())
}

// parseAuditEventFromCloudWatch parses EKS audit log format
func parseAuditEventFromCloudWatch(message string) (Event, error) {
	var raw struct {
		Kind                     string    `json:"kind"`
		APIVersion               string    `json:"apiVersion"`
		Level                    string    `json:"level"`
		AuditID                  string    `json:"auditID"`
		Stage                    string    `json:"stage"`
		RequestURI               string    `json:"requestURI"`
		Verb                     string    `json:"verb"`
		User                     UserInfo  `json:"user"`
		SourceIPs                []string  `json:"sourceIPs"`
		ObjectRef                ObjectReference `json:"objectRef"`
		ResponseStatus           ResponseStatus  `json:"responseStatus"`
		RequestReceivedTimestamp string    `json:"requestReceivedTimestamp"`
		StageTimestamp           string    `json:"stageTimestamp"`
	}

	if err := json.Unmarshal([]byte(message), &raw); err != nil {
		return Event{}, err
	}

	timestamp, _ := time.Parse(time.RFC3339Nano, raw.RequestReceivedTimestamp)

	return Event{
		Timestamp:      timestamp,
		AuditID:        raw.AuditID,
		Stage:          raw.Stage,
		RequestURI:     raw.RequestURI,
		Verb:           raw.Verb,
		User:           raw.User,
		SourceIPs:      raw.SourceIPs,
		ObjectRef:      raw.ObjectRef,
		ResponseStatus: raw.ResponseStatus,
	}, nil
}
