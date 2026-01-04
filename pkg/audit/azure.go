package audit

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/Azure/azure-sdk-for-go/sdk/azcore/policy"
	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
)

type AzureLogAnalyticsSource struct {
	workspaceID string
	cred        *azidentity.DefaultAzureCredential
	httpClient  *http.Client
}

func NewAzureLogAnalyticsSource(workspaceID string) (*AzureLogAnalyticsSource, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	return &AzureLogAnalyticsSource{
		workspaceID: workspaceID,
		cred:        cred,
		httpClient:  &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *AzureLogAnalyticsSource) Name() string {
	return "azure-log-analytics"
}

func (s *AzureLogAnalyticsSource) GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error) {
	token, err := s.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://api.loganalytics.io/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	query := fmt.Sprintf(`
		AzureDiagnostics
		| where Category == "kube-audit"
		| where TimeGenerated between (datetime(%s) .. datetime(%s))
		| extend parsed = parse_json(log_s)
		| project
			TimeGenerated,
			verb = tostring(parsed.verb),
			user = tostring(parsed.user.username),
			resource = tostring(parsed.objectRef.resource),
			namespace = tostring(parsed.objectRef.namespace),
			name = tostring(parsed.objectRef.name),
			apiGroup = tostring(parsed.objectRef.apiGroup),
			statusCode = toint(parsed.responseStatus.code)
		| limit 10000
	`, opts.StartTime.Format(time.RFC3339), opts.EndTime.Format(time.RFC3339))

	reqURL := fmt.Sprintf("https://api.loganalytics.io/v1/workspaces/%s/query", s.workspaceID)
	body := fmt.Sprintf(`{"query": %q}`, query)

	req, err := http.NewRequestWithContext(ctx, "POST", reqURL, strings.NewReader(body))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query Log Analytics: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Log Analytics query failed with status %d", resp.StatusCode)
	}

	var result logAnalyticsResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	return s.parseResponse(result)
}

func (s *AzureLogAnalyticsSource) StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error) {
	ch := make(chan Event)
	go func() {
		defer close(ch)
		events, err := s.GetEvents(ctx, opts)
		if err != nil {
			return
		}
		for _, e := range events {
			select {
			case ch <- e:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

func (s *AzureLogAnalyticsSource) Close() error {
	return nil
}

type logAnalyticsResponse struct {
	Tables []struct {
		Columns []struct {
			Name string `json:"name"`
			Type string `json:"type"`
		} `json:"columns"`
		Rows [][]interface{} `json:"rows"`
	} `json:"tables"`
}

func (s *AzureLogAnalyticsSource) parseResponse(resp logAnalyticsResponse) ([]Event, error) {
	if len(resp.Tables) == 0 || len(resp.Tables[0].Rows) == 0 {
		return []Event{}, nil
	}

	table := resp.Tables[0]
	colIndex := make(map[string]int)
	for i, col := range table.Columns {
		colIndex[col.Name] = i
	}

	events := make([]Event, 0, len(table.Rows))
	for _, row := range table.Rows {
		ts, _ := time.Parse(time.RFC3339, getString(row, colIndex["TimeGenerated"]))

		events = append(events, Event{
			Timestamp: ts,
			Verb:      getString(row, colIndex["verb"]),
			User: UserInfo{
				Username: getString(row, colIndex["user"]),
			},
			ObjectRef: ObjectReference{
				Resource:  getString(row, colIndex["resource"]),
				Namespace: getString(row, colIndex["namespace"]),
				Name:      getString(row, colIndex["name"]),
				APIGroup:  getString(row, colIndex["apiGroup"]),
			},
			ResponseStatus: ResponseStatus{
				Code: getInt(row, colIndex["statusCode"]),
			},
		})
	}

	return events, nil
}

func getString(row []interface{}, idx int) string {
	if idx < 0 || idx >= len(row) {
		return ""
	}
	if s, ok := row[idx].(string); ok {
		return s
	}
	return ""
}

func getInt(row []interface{}, idx int) int {
	if idx < 0 || idx >= len(row) {
		return 0
	}
	switch v := row[idx].(type) {
	case float64:
		return int(v)
	case int:
		return v
	}
	return 0
}

type AzureActivityLogSource struct {
	subscriptionID string
	cred           *azidentity.DefaultAzureCredential
	httpClient     *http.Client
}

func NewAzureActivityLogSource(subscriptionID string) (*AzureActivityLogSource, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get Azure credentials: %w", err)
	}

	return &AzureActivityLogSource{
		subscriptionID: subscriptionID,
		cred:           cred,
		httpClient:     &http.Client{Timeout: 30 * time.Second},
	}, nil
}

func (s *AzureActivityLogSource) Name() string {
	return "azure-activity-log"
}

func (s *AzureActivityLogSource) GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error) {
	token, err := s.cred.GetToken(ctx, policy.TokenRequestOptions{
		Scopes: []string{"https://management.azure.com/.default"},
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get token: %w", err)
	}

	filter := fmt.Sprintf("eventTimestamp ge '%s' and eventTimestamp le '%s'",
		opts.StartTime.Format(time.RFC3339), opts.EndTime.Format(time.RFC3339))

	reqURL := fmt.Sprintf(
		"https://management.azure.com/subscriptions/%s/providers/Microsoft.Insights/eventtypes/management/values?api-version=2015-04-01&$filter=%s",
		s.subscriptionID,
		url.QueryEscape(filter),
	)

	req, err := http.NewRequestWithContext(ctx, "GET", reqURL, nil)
	if err != nil {
		return nil, err
	}

	req.Header.Set("Authorization", "Bearer "+token.Token)

	resp, err := s.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to query Activity Log: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("Activity Log query failed with status %d", resp.StatusCode)
	}

	var result activityLogResponse
	if err := json.NewDecoder(resp.Body).Decode(&result); err != nil {
		return nil, fmt.Errorf("failed to decode response: %w", err)
	}

	events := make([]Event, 0, len(result.Value))
	for _, entry := range result.Value {
		events = append(events, Event{
			Timestamp: entry.EventTimestamp,
			Verb:      entry.OperationName.LocalizedValue,
			User: UserInfo{
				Username: entry.Caller,
			},
			ObjectRef: ObjectReference{
				Resource: entry.ResourceType.Value,
				Name:     entry.ResourceID,
				APIGroup: "azure",
			},
		})
	}

	return events, nil
}

func (s *AzureActivityLogSource) StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error) {
	ch := make(chan Event)
	go func() {
		defer close(ch)
		events, err := s.GetEvents(ctx, opts)
		if err != nil {
			return
		}
		for _, e := range events {
			select {
			case ch <- e:
			case <-ctx.Done():
				return
			}
		}
	}()
	return ch, nil
}

func (s *AzureActivityLogSource) Close() error {
	return nil
}

type activityLogResponse struct {
	Value []struct {
		EventTimestamp time.Time `json:"eventTimestamp"`
		Caller         string    `json:"caller"`
		OperationName  struct {
			Value          string `json:"value"`
			LocalizedValue string `json:"localizedValue"`
		} `json:"operationName"`
		ResourceType struct {
			Value          string `json:"value"`
			LocalizedValue string `json:"localizedValue"`
		} `json:"resourceType"`
		ResourceID string `json:"resourceId"`
	} `json:"value"`
}
