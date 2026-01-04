package audit

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"
)

type FileSource struct {
	paths []string
}

func NewFileSource(paths ...string) *FileSource {
	return &FileSource{paths: paths}
}

func (f *FileSource) Name() string {
	return "file"
}

func (f *FileSource) GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error) {
	var allEvents []Event

	for _, path := range f.paths {
		events, err := f.parseFile(ctx, path, opts)
		if err != nil {
			continue
		}
		allEvents = append(allEvents, events...)
	}

	if opts.Limit > 0 && len(allEvents) > opts.Limit {
		allEvents = allEvents[:opts.Limit]
	}

	return allEvents, nil
}

func (f *FileSource) parseFile(ctx context.Context, path string, opts QueryOptions) ([]Event, error) {
	file, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var events []Event
	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return events, ctx.Err()
		default:
		}

		line := scanner.Text()
		if line == "" {
			continue
		}

		event, err := parseAuditEvent(line)
		if err != nil {
			continue
		}

		if matchesQuery(event, opts) {
			events = append(events, event)
		}
	}

	return events, scanner.Err()
}

func (f *FileSource) StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error) {
	ch := make(chan Event, 100)

	go func() {
		defer close(ch)

		for _, path := range f.paths {
			if err := f.streamFile(ctx, path, opts, ch); err != nil {
				return
			}
		}
	}()

	return ch, nil
}

func (f *FileSource) streamFile(ctx context.Context, path string, opts QueryOptions, ch chan<- Event) error {
	file, err := os.Open(path)
	if err != nil {
		return err
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	scanner.Buffer(make([]byte, 1024*1024), 10*1024*1024)

	for scanner.Scan() {
		select {
		case <-ctx.Done():
			return ctx.Err()
		default:
		}

		event, err := parseAuditEvent(scanner.Text())
		if err != nil {
			continue
		}

		if matchesQuery(event, opts) {
			select {
			case ch <- event:
			case <-ctx.Done():
				return ctx.Err()
			}
		}
	}

	return scanner.Err()
}

func (f *FileSource) Close() error {
	return nil
}

type DirectorySource struct {
	dir     string
	pattern string
}

func NewDirectorySource(dir, pattern string) *DirectorySource {
	if pattern == "" {
		pattern = "*.log"
	}
	return &DirectorySource{dir: dir, pattern: pattern}
}

func (d *DirectorySource) Name() string {
	return "directory"
}

func (d *DirectorySource) GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error) {
	files, err := filepath.Glob(filepath.Join(d.dir, d.pattern))
	if err != nil {
		return nil, err
	}

	fileSource := NewFileSource(files...)
	return fileSource.GetEvents(ctx, opts)
}

func (d *DirectorySource) StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error) {
	files, err := filepath.Glob(filepath.Join(d.dir, d.pattern))
	if err != nil {
		return nil, err
	}

	fileSource := NewFileSource(files...)
	return fileSource.StreamEvents(ctx, opts)
}

func (d *DirectorySource) Close() error {
	return nil
}

type ElasticsearchSource struct {
	endpoint string
	index    string
	client   *http.Client
	username string
	password string
}

func NewElasticsearchSource(endpoint, index, username, password string) *ElasticsearchSource {
	return &ElasticsearchSource{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		index:    index,
		client:   &http.Client{Timeout: 30 * time.Second},
		username: username,
		password: password,
	}
}

func (e *ElasticsearchSource) Name() string {
	return "elasticsearch"
}

func (e *ElasticsearchSource) GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error) {
	query := e.buildQuery(opts)

	url := fmt.Sprintf("%s/%s/_search", e.endpoint, e.index)
	req, err := http.NewRequestWithContext(ctx, "POST", url, strings.NewReader(query))
	if err != nil {
		return nil, err
	}

	req.Header.Set("Content-Type", "application/json")
	if e.username != "" {
		req.SetBasicAuth(e.username, e.password)
	}

	resp, err := e.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("elasticsearch error: %s - %s", resp.Status, string(body))
	}

	return e.parseResponse(resp.Body)
}

func (e *ElasticsearchSource) buildQuery(opts QueryOptions) string {
	must := []string{}

	if !opts.StartTime.IsZero() && !opts.EndTime.IsZero() {
		must = append(must, fmt.Sprintf(`{"range":{"@timestamp":{"gte":"%s","lte":"%s"}}}`,
			opts.StartTime.Format(time.RFC3339), opts.EndTime.Format(time.RFC3339)))
	}

	if opts.Namespace != "" {
		must = append(must, fmt.Sprintf(`{"term":{"objectRef.namespace":"%s"}}`, opts.Namespace))
	}

	if opts.User != "" {
		must = append(must, fmt.Sprintf(`{"term":{"user.username":"%s"}}`, opts.User))
	}

	if opts.Resource != "" {
		must = append(must, fmt.Sprintf(`{"term":{"objectRef.resource":"%s"}}`, opts.Resource))
	}

	if opts.Verb != "" {
		must = append(must, fmt.Sprintf(`{"term":{"verb":"%s"}}`, opts.Verb))
	}

	if !opts.IncludeSystem {
		must = append(must, `{"bool":{"must_not":{"prefix":{"objectRef.namespace":"kube-"}}}}`)
	}

	mustClause := "[]"
	if len(must) > 0 {
		mustClause = "[" + strings.Join(must, ",") + "]"
	}

	size := 1000
	if opts.Limit > 0 {
		size = opts.Limit
	}

	return fmt.Sprintf(`{
		"query": {"bool": {"must": %s}},
		"size": %d,
		"sort": [{"@timestamp": "desc"}]
	}`, mustClause, size)
}

func (e *ElasticsearchSource) parseResponse(body io.Reader) ([]Event, error) {
	var result struct {
		Hits struct {
			Hits []struct {
				Source json.RawMessage `json:"_source"`
			} `json:"hits"`
		} `json:"hits"`
	}

	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return nil, err
	}

	events := make([]Event, 0, len(result.Hits.Hits))
	for _, hit := range result.Hits.Hits {
		event, err := parseAuditEvent(string(hit.Source))
		if err != nil {
			continue
		}
		events = append(events, event)
	}

	return events, nil
}

func (e *ElasticsearchSource) StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error) {
	ch := make(chan Event, 100)

	go func() {
		defer close(ch)

		events, err := e.GetEvents(ctx, opts)
		if err != nil {
			return
		}

		for _, event := range events {
			select {
			case ch <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

func (e *ElasticsearchSource) Close() error {
	return nil
}

type LokiSource struct {
	endpoint string
	client   *http.Client
	orgID    string
}

func NewLokiSource(endpoint, orgID string) *LokiSource {
	return &LokiSource{
		endpoint: strings.TrimSuffix(endpoint, "/"),
		client:   &http.Client{Timeout: 30 * time.Second},
		orgID:    orgID,
	}
}

func (l *LokiSource) Name() string {
	return "loki"
}

func (l *LokiSource) GetEvents(ctx context.Context, opts QueryOptions) ([]Event, error) {
	query := `{job="kube-apiserver"} |= "audit"`

	if opts.Namespace != "" {
		query += fmt.Sprintf(` |= "%s"`, opts.Namespace)
	}

	start := opts.StartTime
	if start.IsZero() {
		start = time.Now().Add(-24 * time.Hour)
	}
	end := opts.EndTime
	if end.IsZero() {
		end = time.Now()
	}

	limit := 1000
	if opts.Limit > 0 {
		limit = opts.Limit
	}

	url := fmt.Sprintf("%s/loki/api/v1/query_range?query=%s&start=%d&end=%d&limit=%d",
		l.endpoint,
		query,
		start.UnixNano(),
		end.UnixNano(),
		limit)

	req, err := http.NewRequestWithContext(ctx, "GET", url, nil)
	if err != nil {
		return nil, err
	}

	if l.orgID != "" {
		req.Header.Set("X-Scope-OrgID", l.orgID)
	}

	resp, err := l.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return nil, fmt.Errorf("loki error: %s - %s", resp.Status, string(body))
	}

	return l.parseResponse(resp.Body, opts)
}

func (l *LokiSource) parseResponse(body io.Reader, opts QueryOptions) ([]Event, error) {
	var result struct {
		Data struct {
			Result []struct {
				Values [][]string `json:"values"`
			} `json:"result"`
		} `json:"data"`
	}

	if err := json.NewDecoder(body).Decode(&result); err != nil {
		return nil, err
	}

	var events []Event
	for _, stream := range result.Data.Result {
		for _, entry := range stream.Values {
			if len(entry) < 2 {
				continue
			}

			event, err := parseAuditEvent(entry[1])
			if err != nil {
				continue
			}

			if matchesQuery(event, opts) {
				events = append(events, event)
			}
		}
	}

	return events, nil
}

func (l *LokiSource) StreamEvents(ctx context.Context, opts QueryOptions) (<-chan Event, error) {
	ch := make(chan Event, 100)

	go func() {
		defer close(ch)

		events, err := l.GetEvents(ctx, opts)
		if err != nil {
			return
		}

		for _, event := range events {
			select {
			case ch <- event:
			case <-ctx.Done():
				return
			}
		}
	}()

	return ch, nil
}

func (l *LokiSource) Close() error {
	return nil
}

func parseAuditEvent(data string) (Event, error) {
	var raw struct {
		AuditID           string    `json:"auditID"`
		Stage             string    `json:"stage"`
		RequestURI        string    `json:"requestURI"`
		Verb              string    `json:"verb"`
		Timestamp         time.Time `json:"requestReceivedTimestamp"`
		StageTimestamp    time.Time `json:"stageTimestamp"`
		User              struct {
			Username string              `json:"username"`
			UID      string              `json:"uid"`
			Groups   []string            `json:"groups"`
			Extra    map[string][]string `json:"extra"`
		} `json:"user"`
		SourceIPs []string `json:"sourceIPs"`
		ObjectRef struct {
			Resource        string `json:"resource"`
			Namespace       string `json:"namespace"`
			Name            string `json:"name"`
			UID             string `json:"uid"`
			APIGroup        string `json:"apiGroup"`
			APIVersion      string `json:"apiVersion"`
			ResourceVersion string `json:"resourceVersion"`
			Subresource     string `json:"subresource"`
		} `json:"objectRef"`
		ResponseStatus struct {
			Code    int    `json:"code"`
			Status  string `json:"status"`
			Message string `json:"message"`
			Reason  string `json:"reason"`
		} `json:"responseStatus"`
		RequestObject  map[string]interface{} `json:"requestObject"`
		ResponseObject map[string]interface{} `json:"responseObject"`
		Annotations    map[string]string      `json:"annotations"`
	}

	if err := json.Unmarshal([]byte(data), &raw); err != nil {
		return Event{}, err
	}

	timestamp := raw.Timestamp
	if timestamp.IsZero() {
		timestamp = raw.StageTimestamp
	}

	return Event{
		Timestamp: timestamp,
		AuditID:   raw.AuditID,
		Stage:     raw.Stage,
		RequestURI: raw.RequestURI,
		Verb:      raw.Verb,
		User: UserInfo{
			Username: raw.User.Username,
			UID:      raw.User.UID,
			Groups:   raw.User.Groups,
			Extra:    raw.User.Extra,
		},
		SourceIPs: raw.SourceIPs,
		ObjectRef: ObjectReference{
			Resource:        raw.ObjectRef.Resource,
			Namespace:       raw.ObjectRef.Namespace,
			Name:            raw.ObjectRef.Name,
			UID:             raw.ObjectRef.UID,
			APIGroup:        raw.ObjectRef.APIGroup,
			APIVersion:      raw.ObjectRef.APIVersion,
			ResourceVersion: raw.ObjectRef.ResourceVersion,
			Subresource:     raw.ObjectRef.Subresource,
		},
		ResponseStatus: ResponseStatus{
			Code:    raw.ResponseStatus.Code,
			Status:  raw.ResponseStatus.Status,
			Message: raw.ResponseStatus.Message,
			Reason:  raw.ResponseStatus.Reason,
		},
		RequestObject:  raw.RequestObject,
		ResponseObject: raw.ResponseObject,
		Annotations:    raw.Annotations,
	}, nil
}

func matchesQuery(event Event, opts QueryOptions) bool {
	if !opts.StartTime.IsZero() && event.Timestamp.Before(opts.StartTime) {
		return false
	}

	if !opts.EndTime.IsZero() && event.Timestamp.After(opts.EndTime) {
		return false
	}

	if opts.Namespace != "" && event.ObjectRef.Namespace != opts.Namespace {
		return false
	}

	if opts.User != "" && event.User.Username != opts.User {
		return false
	}

	if opts.Resource != "" && event.ObjectRef.Resource != opts.Resource {
		return false
	}

	if opts.Verb != "" && event.Verb != opts.Verb {
		return false
	}

	if !opts.IncludeSystem {
		if strings.HasPrefix(event.ObjectRef.Namespace, "kube-") {
			return false
		}
		if strings.HasPrefix(event.User.Username, "system:") && !strings.HasPrefix(event.User.Username, "system:serviceaccount:") {
			return false
		}
	}

	return true
}
