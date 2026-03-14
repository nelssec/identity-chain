package watch

import (
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"sync"
	"testing"
)

func TestNewWebhookNotifier(t *testing.T) {
	headers := map[string]string{"Authorization": "Bearer token123"}
	w := NewWebhookNotifier("http://example.com/hook", headers)

	if w == nil {
		t.Fatal("NewWebhookNotifier returned nil")
	}
	if w.url != "http://example.com/hook" {
		t.Errorf("unexpected url: %s", w.url)
	}
	if w.headers["Authorization"] != "Bearer token123" {
		t.Error("headers not set correctly")
	}
	if w.client == nil {
		t.Error("client should not be nil")
	}
}

func TestWebhookSendEmptyFindings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewWebhookNotifier(srv.URL, nil)
	notifier.Send([]FindingChange{})

	if called {
		t.Error("Send should not call webhook with empty findings")
	}
}

func TestWebhookSendNilFindings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewWebhookNotifier(srv.URL, nil)
	notifier.Send(nil)

	if called {
		t.Error("Send should not call webhook with nil findings")
	}
}

func TestWebhookSendPayload(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte
	var receivedHeaders http.Header

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		receivedHeaders = r.Header.Clone()
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	headers := map[string]string{"X-Custom": "test-value"}
	notifier := NewWebhookNotifier(srv.URL, headers)

	findings := []FindingChange{
		{Type: "rbac", CheckID: "RBAC001", Name: "Wildcard access", Severity: "critical", Affected: "default/admin"},
		{Type: "rbac", CheckID: "RBAC002", Name: "High privilege", Severity: "high", Affected: "default/app"},
		{Type: "pod_security", CheckID: "PSS001", Name: "Privileged container", Severity: "medium", Affected: "default/web"},
	}

	notifier.Send(findings)

	mu.Lock()
	defer mu.Unlock()

	// Verify Content-Type
	if receivedHeaders.Get("Content-Type") != "application/json" {
		t.Errorf("expected Content-Type application/json, got %s", receivedHeaders.Get("Content-Type"))
	}

	// Verify custom header
	if receivedHeaders.Get("X-Custom") != "test-value" {
		t.Errorf("expected X-Custom header, got %s", receivedHeaders.Get("X-Custom"))
	}

	// Parse payload
	var payload WebhookPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal payload: %v", err)
	}

	if payload.Event != "new_findings" {
		t.Errorf("expected event 'new_findings', got %q", payload.Event)
	}
	if payload.Timestamp.IsZero() {
		t.Error("timestamp should not be zero")
	}
	if len(payload.Findings) != 3 {
		t.Errorf("expected 3 findings, got %d", len(payload.Findings))
	}
	if payload.Summary.NewFindings != 3 {
		t.Errorf("expected NewFindings=3, got %d", payload.Summary.NewFindings)
	}
	if payload.Summary.CriticalCount != 1 {
		t.Errorf("expected CriticalCount=1, got %d", payload.Summary.CriticalCount)
	}
	if payload.Summary.HighCount != 1 {
		t.Errorf("expected HighCount=1, got %d", payload.Summary.HighCount)
	}

	// Verify individual finding fields
	f := payload.Findings[0]
	if f.Type != "rbac" || f.CheckID != "RBAC001" || f.Severity != "critical" {
		t.Errorf("unexpected first finding: %+v", f)
	}
}

func TestSlackSendEmptyFindings(t *testing.T) {
	called := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		called = true
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewWebhookNotifier(srv.URL, nil)
	notifier.SendSlack([]FindingChange{})

	if called {
		t.Error("SendSlack should not call webhook with empty findings")
	}
}

func TestSlackSendPayload(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewWebhookNotifier(srv.URL, nil)

	findings := []FindingChange{
		{Type: "rbac", CheckID: "RBAC001", Name: "Wildcard access", Severity: "critical", Affected: "default/admin"},
		{Type: "rbac", CheckID: "RBAC002", Name: "High privilege", Severity: "high", Affected: "default/app"},
	}

	notifier.SendSlack(findings)

	mu.Lock()
	defer mu.Unlock()

	var payload SlackPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal slack payload: %v", err)
	}

	if payload.Text == "" {
		t.Error("slack text should not be empty")
	}
	if !contains(payload.Text, "2 new security findings") {
		t.Errorf("unexpected text: %s", payload.Text)
	}

	if len(payload.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(payload.Attachments))
	}

	att := payload.Attachments[0]
	if att.Color != "danger" {
		t.Errorf("expected color 'danger' for critical finding, got %q", att.Color)
	}
	if att.Footer != "Identity Chain Watcher" {
		t.Errorf("unexpected footer: %s", att.Footer)
	}
	if !contains(att.Title, "1 Critical") || !contains(att.Title, "1 High") {
		t.Errorf("unexpected title: %s", att.Title)
	}
}

func TestSlackSendWarningColor(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewWebhookNotifier(srv.URL, nil)

	// Only high severity, no critical -- should use "warning" color
	findings := []FindingChange{
		{Type: "rbac", CheckID: "RBAC002", Name: "High privilege", Severity: "high", Affected: "default/app"},
	}

	notifier.SendSlack(findings)

	mu.Lock()
	defer mu.Unlock()

	var payload SlackPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal slack payload: %v", err)
	}

	if len(payload.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(payload.Attachments))
	}
	if payload.Attachments[0].Color != "warning" {
		t.Errorf("expected 'warning' color with no critical findings, got %q", payload.Attachments[0].Color)
	}
}

func TestSlackSendManyFindings(t *testing.T) {
	var mu sync.Mutex
	var receivedBody []byte

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		defer mu.Unlock()
		var err error
		receivedBody, err = io.ReadAll(r.Body)
		if err != nil {
			t.Errorf("failed to read body: %v", err)
		}
		w.WriteHeader(http.StatusOK)
	}))
	defer srv.Close()

	notifier := NewWebhookNotifier(srv.URL, nil)

	// More than 5 findings to test truncation
	findings := make([]FindingChange, 8)
	for i := range findings {
		findings[i] = FindingChange{
			Type:     "rbac",
			CheckID:  "RBAC001",
			Name:     "Test finding",
			Severity: "high",
			Affected: "default/test",
		}
	}

	notifier.SendSlack(findings)

	mu.Lock()
	defer mu.Unlock()

	var payload SlackPayload
	if err := json.Unmarshal(receivedBody, &payload); err != nil {
		t.Fatalf("failed to unmarshal slack payload: %v", err)
	}

	// The attachment text should contain "... and 3 more"
	if len(payload.Attachments) != 1 {
		t.Fatalf("expected 1 attachment, got %d", len(payload.Attachments))
	}
	if !contains(payload.Attachments[0].Text, "and 3 more") {
		t.Errorf("expected truncation message, got: %s", payload.Attachments[0].Text)
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsSubstring(s, substr))
}

func containsSubstring(s, sub string) bool {
	for i := 0; i <= len(s)-len(sub); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}
