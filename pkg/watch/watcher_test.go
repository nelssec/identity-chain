package watch

import (
	"sync/atomic"
	"testing"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestNewDebouncer(t *testing.T) {
	called := make(chan struct{}, 1)
	d := newDebouncer(50*time.Millisecond, func() {
		called <- struct{}{}
	})

	if d == nil {
		t.Fatal("newDebouncer returned nil")
	}
	if d.period != 50*time.Millisecond {
		t.Errorf("expected period 50ms, got %v", d.period)
	}
	if d.callback == nil {
		t.Error("callback should not be nil")
	}
}

func TestDebouncerTriggerCallsCallback(t *testing.T) {
	var count atomic.Int32
	done := make(chan struct{}, 1)

	d := newDebouncer(50*time.Millisecond, func() {
		count.Add(1)
		select {
		case done <- struct{}{}:
		default:
		}
	})

	d.trigger()

	select {
	case <-done:
		// callback was called
	case <-time.After(500 * time.Millisecond):
		t.Fatal("callback was not called within timeout")
	}

	if got := count.Load(); got != 1 {
		t.Errorf("expected callback called once, got %d", got)
	}
}

func TestDebouncerResetOnMultipleTriggers(t *testing.T) {
	var count atomic.Int32
	done := make(chan struct{}, 10)

	d := newDebouncer(100*time.Millisecond, func() {
		count.Add(1)
		done <- struct{}{}
	})

	// Trigger rapidly -- the debouncer should reset each time, so only
	// the last trigger's timer fires.
	for i := 0; i < 5; i++ {
		d.trigger()
		time.Sleep(20 * time.Millisecond)
	}

	select {
	case <-done:
	case <-time.After(500 * time.Millisecond):
		t.Fatal("callback was not called within timeout")
	}

	// Allow a small window for any extra calls
	time.Sleep(150 * time.Millisecond)

	if got := count.Load(); got != 1 {
		t.Errorf("expected callback called once due to debouncing, got %d", got)
	}
}

func TestCountSeverity(t *testing.T) {
	w := &Watcher{}

	tests := []struct {
		severity string
		field    string
	}{
		{"critical", "CriticalCount"},
		{"high", "HighCount"},
		{"medium", "MediumCount"},
		{"low", "LowCount"},
		{"unknown", "none"},
	}

	for _, tt := range tests {
		t.Run(tt.severity, func(t *testing.T) {
			s := &StateSummary{}
			w.countSeverity(s, tt.severity)

			switch tt.severity {
			case "critical":
				if s.CriticalCount != 1 {
					t.Errorf("expected CriticalCount=1, got %d", s.CriticalCount)
				}
			case "high":
				if s.HighCount != 1 {
					t.Errorf("expected HighCount=1, got %d", s.HighCount)
				}
			case "medium":
				if s.MediumCount != 1 {
					t.Errorf("expected MediumCount=1, got %d", s.MediumCount)
				}
			case "low":
				if s.LowCount != 1 {
					t.Errorf("expected LowCount=1, got %d", s.LowCount)
				}
			case "unknown":
				// No field should be incremented
				if s.CriticalCount+s.HighCount+s.MediumCount+s.LowCount != 0 {
					t.Error("unknown severity should not increment any count")
				}
			}
		})
	}
}

func TestCountSeverityMultiple(t *testing.T) {
	w := &Watcher{}
	s := &StateSummary{}

	w.countSeverity(s, "critical")
	w.countSeverity(s, "critical")
	w.countSeverity(s, "high")
	w.countSeverity(s, "medium")
	w.countSeverity(s, "medium")
	w.countSeverity(s, "medium")
	w.countSeverity(s, "low")

	if s.CriticalCount != 2 {
		t.Errorf("expected CriticalCount=2, got %d", s.CriticalCount)
	}
	if s.HighCount != 1 {
		t.Errorf("expected HighCount=1, got %d", s.HighCount)
	}
	if s.MediumCount != 3 {
		t.Errorf("expected MediumCount=3, got %d", s.MediumCount)
	}
	if s.LowCount != 1 {
		t.Errorf("expected LowCount=1, got %d", s.LowCount)
	}
}

func TestDiffFindingsNewRBAC(t *testing.T) {
	w := &Watcher{}

	oldState := &WatchState{
		RBACFindings: []analysis.RBACFinding{
			{
				CheckID:  "RBAC001",
				Title:    "Existing finding",
				Severity: graph.SeverityHigh,
				Affected: []analysis.AffectedResource{
					{Namespace: "default", Name: "sa1"},
				},
			},
		},
	}

	newState := &WatchState{
		RBACFindings: []analysis.RBACFinding{
			{
				CheckID:  "RBAC001",
				Title:    "Existing finding",
				Severity: graph.SeverityHigh,
				Affected: []analysis.AffectedResource{
					{Namespace: "default", Name: "sa1"},
				},
			},
			{
				CheckID:  "RBAC002",
				Title:    "New finding",
				Severity: graph.SeverityCritical,
				Affected: []analysis.AffectedResource{
					{Namespace: "kube-system", Name: "admin"},
				},
			},
		},
	}

	changes := w.diffFindings(oldState, newState)

	if len(changes) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(changes))
	}
	if changes[0].CheckID != "RBAC002" {
		t.Errorf("expected CheckID RBAC002, got %s", changes[0].CheckID)
	}
	if changes[0].Type != "rbac" {
		t.Errorf("expected type 'rbac', got %s", changes[0].Type)
	}
	if changes[0].Severity != "critical" {
		t.Errorf("expected severity 'critical', got %s", changes[0].Severity)
	}
	if changes[0].Affected != "kube-system/admin" {
		t.Errorf("expected affected 'kube-system/admin', got %s", changes[0].Affected)
	}
}

func TestDiffFindingsNewPodSec(t *testing.T) {
	w := &Watcher{}

	oldState := &WatchState{
		PodSecFindings: []analysis.PodSecurityFinding{},
	}

	newState := &WatchState{
		PodSecFindings: []analysis.PodSecurityFinding{
			{
				CheckID:  "PSS001",
				Title:    "Privileged container",
				Severity: graph.SeverityCritical,
				Affected: []analysis.AffectedWorkload{
					{Namespace: "prod", Name: "web-app"},
				},
			},
		},
	}

	changes := w.diffFindings(oldState, newState)

	if len(changes) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(changes))
	}
	if changes[0].CheckID != "PSS001" {
		t.Errorf("expected CheckID PSS001, got %s", changes[0].CheckID)
	}
	if changes[0].Type != "pod_security" {
		t.Errorf("expected type 'pod_security', got %s", changes[0].Type)
	}
	if changes[0].Affected != "prod/web-app" {
		t.Errorf("expected affected 'prod/web-app', got %s", changes[0].Affected)
	}
}

func TestDiffFindingsNoChanges(t *testing.T) {
	w := &Watcher{}

	state := &WatchState{
		RBACFindings: []analysis.RBACFinding{
			{
				CheckID:  "RBAC001",
				Severity: graph.SeverityHigh,
				Affected: []analysis.AffectedResource{
					{Namespace: "default", Name: "sa1"},
				},
			},
		},
		PodSecFindings: []analysis.PodSecurityFinding{
			{
				CheckID:  "PSS001",
				Severity: graph.SeverityMedium,
				Affected: []analysis.AffectedWorkload{
					{Namespace: "default", Name: "web"},
				},
			},
		},
	}

	changes := w.diffFindings(state, state)

	if len(changes) != 0 {
		t.Errorf("expected 0 changes when states are the same, got %d", len(changes))
	}
}

func TestDiffFindingsEmptyAffected(t *testing.T) {
	w := &Watcher{}

	oldState := &WatchState{
		RBACFindings: []analysis.RBACFinding{
			{CheckID: "RBAC001", Severity: graph.SeverityHigh, Affected: nil},
		},
	}

	newState := &WatchState{
		RBACFindings: []analysis.RBACFinding{
			{CheckID: "RBAC001", Severity: graph.SeverityHigh, Affected: nil},
			{CheckID: "RBAC002", Severity: graph.SeverityCritical, Affected: nil},
		},
	}

	changes := w.diffFindings(oldState, newState)

	if len(changes) != 1 {
		t.Fatalf("expected 1 change, got %d", len(changes))
	}
	if changes[0].CheckID != "RBAC002" {
		t.Errorf("expected RBAC002, got %s", changes[0].CheckID)
	}
	if changes[0].Affected != "" {
		t.Errorf("expected empty affected, got %q", changes[0].Affected)
	}
}

func TestFindingKey(t *testing.T) {
	tests := []struct {
		name     string
		affected []analysis.AffectedResource
		want     string
	}{
		{"nil", nil, ""},
		{"empty", []analysis.AffectedResource{}, ""},
		{"single", []analysis.AffectedResource{{Namespace: "ns", Name: "sa"}}, "ns/sa"},
		{"cluster-scoped", []analysis.AffectedResource{{Name: "admin"}}, "/admin"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := findingKey(tt.affected)
			if got != tt.want {
				t.Errorf("findingKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestPodSecFindingKey(t *testing.T) {
	tests := []struct {
		name     string
		affected []analysis.AffectedWorkload
		want     string
	}{
		{"nil", nil, ""},
		{"empty", []analysis.AffectedWorkload{}, ""},
		{"single", []analysis.AffectedWorkload{{Namespace: "prod", Name: "web"}}, "prod/web"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := podSecFindingKey(tt.affected)
			if got != tt.want {
				t.Errorf("podSecFindingKey() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatAffected(t *testing.T) {
	tests := []struct {
		name     string
		affected []analysis.AffectedResource
		want     string
	}{
		{"nil", nil, ""},
		{"empty", []analysis.AffectedResource{}, ""},
		{"with-namespace", []analysis.AffectedResource{{Namespace: "ns", Name: "sa"}}, "ns/sa"},
		{"without-namespace", []analysis.AffectedResource{{Name: "cluster-role"}}, "cluster-role"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatAffected(tt.affected)
			if got != tt.want {
				t.Errorf("formatAffected() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestFormatPodSecAffected(t *testing.T) {
	tests := []struct {
		name     string
		affected []analysis.AffectedWorkload
		want     string
	}{
		{"nil", nil, ""},
		{"empty", []analysis.AffectedWorkload{}, ""},
		{"with-namespace", []analysis.AffectedWorkload{{Namespace: "prod", Name: "deploy"}}, "prod/deploy"},
		{"without-namespace", []analysis.AffectedWorkload{{Name: "deploy"}}, "deploy"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := formatPodSecAffected(tt.affected)
			if got != tt.want {
				t.Errorf("formatPodSecAffected() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestConfigStruct(t *testing.T) {
	cfg := Config{}

	// Verify zero values
	if cfg.Kubeconfig != "" {
		t.Error("expected empty Kubeconfig")
	}
	if cfg.AllNamespaces {
		t.Error("expected AllNamespaces false by default")
	}
	if cfg.IncludeSystem {
		t.Error("expected IncludeSystem false by default")
	}
	if cfg.ResyncPeriod != 0 {
		t.Error("expected zero ResyncPeriod")
	}
	if cfg.DebouncePeriod != 0 {
		t.Error("expected zero DebouncePeriod")
	}
	if cfg.MaxMemoryMB != 0 {
		t.Error("expected zero MaxMemoryMB")
	}
}

func TestWatchStateStruct(t *testing.T) {
	now := time.Now()
	state := &WatchState{
		Timestamp: now,
		Summary: StateSummary{
			TotalFindings: 10,
			CriticalCount: 1,
			HighCount:     2,
			MediumCount:   3,
			LowCount:      4,
			WorkloadCount: 5,
			SACount:       6,
			RoleCount:     7,
		},
	}

	if state.Timestamp != now {
		t.Error("timestamp mismatch")
	}
	if state.Summary.TotalFindings != 10 {
		t.Error("TotalFindings mismatch")
	}
}

func TestFindingChangeStruct(t *testing.T) {
	fc := FindingChange{
		Type:     "rbac",
		CheckID:  "RBAC001",
		Name:     "Test",
		Severity: "critical",
		Affected: "default/sa",
	}

	if fc.Type != "rbac" {
		t.Error("Type mismatch")
	}
	if fc.CheckID != "RBAC001" {
		t.Error("CheckID mismatch")
	}
}
