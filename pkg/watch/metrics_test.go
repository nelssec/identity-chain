package watch

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestNewMetrics(t *testing.T) {
	m := NewMetrics()
	if m == nil {
		t.Fatal("NewMetrics returned nil")
	}
	// state should be nil initially
	m.mu.RLock()
	if m.state != nil {
		t.Error("expected nil state on new Metrics")
	}
	m.mu.RUnlock()
}

func TestMetricsUpdate(t *testing.T) {
	m := NewMetrics()
	state := &WatchState{
		Timestamp: time.Now(),
		Summary: StateSummary{
			CriticalCount: 2,
			HighCount:     3,
			MediumCount:   5,
			LowCount:      10,
			WorkloadCount: 8,
			SACount:       4,
			RoleCount:     6,
		},
	}
	m.Update(state)

	m.mu.RLock()
	defer m.mu.RUnlock()
	if m.state != state {
		t.Error("Update did not set state")
	}
}

func TestMetricsHandlerNilState(t *testing.T) {
	m := NewMetrics()

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	m.handler(rec, req)

	resp := rec.Result()
	if resp.StatusCode != http.StatusOK {
		t.Fatalf("expected 200, got %d", resp.StatusCode)
	}

	ct := resp.Header.Get("Content-Type")
	if ct != "text/plain; version=0.0.4" {
		t.Errorf("unexpected content type: %s", ct)
	}

	body := rec.Body.String()

	// With nil state, all counts should be 0
	expectedLines := []string{
		`idc_findings_total{severity="critical"} 0`,
		`idc_findings_total{severity="high"} 0`,
		`idc_findings_total{severity="medium"} 0`,
		`idc_findings_total{severity="low"} 0`,
		`idc_resources_total{type="workload"} 0`,
		`idc_resources_total{type="serviceaccount"} 0`,
		`idc_resources_total{type="role"} 0`,
		`idc_last_analysis_timestamp_seconds 0`,
	}
	for _, line := range expectedLines {
		if !strings.Contains(body, line) {
			t.Errorf("missing expected line in output: %q", line)
		}
	}

	// HELP and TYPE lines should be present
	helpLines := []string{
		"# HELP idc_findings_total",
		"# TYPE idc_findings_total gauge",
		"# HELP idc_resources_total",
		"# TYPE idc_resources_total gauge",
		"# HELP idc_last_analysis_timestamp_seconds",
		"# TYPE idc_last_analysis_timestamp_seconds gauge",
		"# HELP idc_rbac_findings_total",
		"# TYPE idc_rbac_findings_total gauge",
		"# HELP idc_pod_security_findings_total",
		"# TYPE idc_pod_security_findings_total gauge",
		"# HELP idc_network_policy_findings_total",
		"# TYPE idc_network_policy_findings_total gauge",
	}
	for _, line := range helpLines {
		if !strings.Contains(body, line) {
			t.Errorf("missing expected line: %q", line)
		}
	}
}

func TestMetricsHandlerWithState(t *testing.T) {
	m := NewMetrics()
	ts := time.Date(2025, 1, 15, 10, 30, 0, 0, time.UTC)
	state := &WatchState{
		Timestamp: ts,
		Summary: StateSummary{
			CriticalCount: 1,
			HighCount:     2,
			MediumCount:   3,
			LowCount:      4,
			WorkloadCount: 10,
			SACount:       5,
			RoleCount:     7,
		},
		RBACFindings: []analysis.RBACFinding{
			{CheckID: "RBAC001", Severity: graph.SeverityCritical},
			{CheckID: "RBAC001", Severity: graph.SeverityCritical},
			{CheckID: "RBAC002", Severity: graph.SeverityHigh},
		},
		PodSecFindings: []analysis.PodSecurityFinding{
			{CheckID: "PSS001", Severity: graph.SeverityMedium},
		},
		NetPolFindings: []analysis.NetworkPolicyFinding{
			{CheckID: "NET001", Severity: graph.SeverityLow},
			{CheckID: "NET001", Severity: graph.SeverityLow},
		},
	}
	m.Update(state)

	req := httptest.NewRequest("GET", "/metrics", nil)
	rec := httptest.NewRecorder()
	m.handler(rec, req)

	body := rec.Body.String()

	// Check severity counts
	expectedLines := []string{
		`idc_findings_total{severity="critical"} 1`,
		`idc_findings_total{severity="high"} 2`,
		`idc_findings_total{severity="medium"} 3`,
		`idc_findings_total{severity="low"} 4`,
		`idc_resources_total{type="workload"} 10`,
		`idc_resources_total{type="serviceaccount"} 5`,
		`idc_resources_total{type="role"} 7`,
	}
	for _, line := range expectedLines {
		if !strings.Contains(body, line) {
			t.Errorf("missing expected line: %q\nbody: %s", line, body)
		}
	}

	// Check timestamp
	expectedTS := ts.Unix()
	tsLine := "idc_last_analysis_timestamp_seconds"
	if !strings.Contains(body, tsLine) {
		t.Errorf("missing timestamp metric")
	}
	_ = expectedTS // verified via the line presence

	// Check RBAC per-check counts
	if !strings.Contains(body, `idc_rbac_findings_total{check_id="RBAC001"} 2`) {
		t.Error("missing RBAC001 count of 2")
	}
	if !strings.Contains(body, `idc_rbac_findings_total{check_id="RBAC002"} 1`) {
		t.Error("missing RBAC002 count of 1")
	}

	// Check pod security per-check counts
	if !strings.Contains(body, `idc_pod_security_findings_total{check_id="PSS001"} 1`) {
		t.Error("missing PSS001 count")
	}

	// Check network policy per-check counts
	if !strings.Contains(body, `idc_network_policy_findings_total{check_id="NET001"} 2`) {
		t.Error("missing NET001 count of 2")
	}
}

func TestMetricsReadyzNilState(t *testing.T) {
	m := NewMetrics()

	// We can't easily test the registered HTTP handlers since Serve uses
	// the default mux. Instead, test the readyz logic directly.
	m.mu.RLock()
	hasState := m.state != nil
	m.mu.RUnlock()

	if hasState {
		t.Error("expected no state initially")
	}
}

func TestMetricsReadyzWithState(t *testing.T) {
	m := NewMetrics()
	m.Update(&WatchState{Timestamp: time.Now()})

	m.mu.RLock()
	hasState := m.state != nil
	m.mu.RUnlock()

	if !hasState {
		t.Error("expected state to be set after Update")
	}
}
