package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestComputeDiff_NilBaseline(t *testing.T) {
	current := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Wildcard verbs", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "default", Name: "admin"}}},
		},
	}

	result := ComputeDiff(nil, current)

	if result.Summary.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", result.Summary.NewCount)
	}
	if result.Summary.ResolvedCount != 0 {
		t.Errorf("expected 0 resolved, got %d", result.Summary.ResolvedCount)
	}
	if result.Summary.Status != "degraded" {
		t.Errorf("expected status degraded, got %s", result.Summary.Status)
	}
}

func TestComputeDiff_Unchanged(t *testing.T) {
	findings := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Wildcard verbs", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "default", Name: "admin"}}},
		},
	}

	result := ComputeDiff(findings, findings)

	if result.Summary.Status != "unchanged" {
		t.Errorf("expected status unchanged, got %s", result.Summary.Status)
	}
	if result.Summary.NewCount != 0 {
		t.Errorf("expected 0 new, got %d", result.Summary.NewCount)
	}
	if result.Summary.ResolvedCount != 0 {
		t.Errorf("expected 0 resolved, got %d", result.Summary.ResolvedCount)
	}
	if result.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.UnchangedCount)
	}
}

func TestComputeDiff_NewFindings(t *testing.T) {
	baseline := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Wildcard verbs", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "default", Name: "admin"}}},
		},
	}

	current := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Wildcard verbs", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "default", Name: "admin"}}},
			{CheckID: "RBAC002", Title: "Cluster admin binding", Severity: graph.SeverityCritical,
				Affected: []AffectedResource{{Namespace: "kube-system", Name: "superuser"}}},
		},
	}

	result := ComputeDiff(baseline, current)

	if result.Summary.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", result.Summary.NewCount)
	}
	if result.Summary.Status != "degraded" {
		t.Errorf("expected status degraded, got %s", result.Summary.Status)
	}
	if len(result.NewFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(result.NewFindings))
	}
	if result.NewFindings[0].CheckID != "RBAC002" {
		t.Errorf("expected new finding RBAC002, got %s", result.NewFindings[0].CheckID)
	}
}

func TestComputeDiff_ResolvedFindings(t *testing.T) {
	baseline := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Wildcard verbs", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "default", Name: "admin"}}},
			{CheckID: "RBAC002", Title: "Cluster admin binding", Severity: graph.SeverityCritical,
				Affected: []AffectedResource{{Namespace: "kube-system", Name: "superuser"}}},
		},
	}

	current := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Wildcard verbs", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "default", Name: "admin"}}},
		},
	}

	result := ComputeDiff(baseline, current)

	if result.Summary.ResolvedCount != 1 {
		t.Errorf("expected 1 resolved finding, got %d", result.Summary.ResolvedCount)
	}
	if result.Summary.Status != "improved" {
		t.Errorf("expected status improved, got %s", result.Summary.Status)
	}
	if len(result.ResolvedFindings) != 1 {
		t.Fatalf("expected 1 resolved finding, got %d", len(result.ResolvedFindings))
	}
	if result.ResolvedFindings[0].CheckID != "RBAC002" {
		t.Errorf("expected resolved finding RBAC002, got %s", result.ResolvedFindings[0].CheckID)
	}
}

func TestComputeDiff_MixedChanges(t *testing.T) {
	baseline := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Wildcard verbs", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "default", Name: "admin"}}},
		},
		PodSecFindings: []PodSecurityFinding{
			{CheckID: "PSS001", Title: "Privileged container", Severity: graph.SeverityCritical,
				Affected: []AffectedWorkload{{Namespace: "default", Name: "app"}}},
		},
	}

	current := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC003", Title: "Secrets access", Severity: graph.SeverityMedium,
				Affected: []AffectedResource{{Namespace: "prod", Name: "reader"}}},
		},
		PodSecFindings: []PodSecurityFinding{
			{CheckID: "PSS001", Title: "Privileged container", Severity: graph.SeverityCritical,
				Affected: []AffectedWorkload{{Namespace: "default", Name: "app"}}},
		},
	}

	result := ComputeDiff(baseline, current)

	if result.Summary.NewCount != 1 {
		t.Errorf("expected 1 new, got %d", result.Summary.NewCount)
	}
	if result.Summary.ResolvedCount != 1 {
		t.Errorf("expected 1 resolved, got %d", result.Summary.ResolvedCount)
	}
	if result.UnchangedCount != 1 {
		t.Errorf("expected 1 unchanged, got %d", result.UnchangedCount)
	}
}

func TestComputeDiff_CrossTypeFindings(t *testing.T) {
	baseline := &ScanFindings{}

	current := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Test", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "ns1", Name: "r1"}}},
		},
		NetPolFindings: []NetworkPolicyFinding{
			{CheckID: "NET001", Title: "No network policy", Severity: graph.SeverityMedium,
				Affected: []AffectedNetworkResource{{Namespace: "ns2", Name: "svc1"}}},
		},
		CloudFindings: []CloudIAMFinding{
			{Title: "Admin role", Provider: "aws", Category: CloudCategoryAdminAccess,
				Severity: graph.SeverityCritical, RoleARN: "arn:aws:iam::role/admin"},
		},
	}

	result := ComputeDiff(baseline, current)

	if result.Summary.NewCount != 3 {
		t.Errorf("expected 3 new findings across types, got %d", result.Summary.NewCount)
	}
	if result.Summary.Status != "degraded" {
		t.Errorf("expected status degraded, got %s", result.Summary.Status)
	}
}

func TestComputeDiff_BothNil(t *testing.T) {
	result := ComputeDiff(nil, nil)

	if result.Summary.Status != "unchanged" {
		t.Errorf("expected unchanged for nil/nil, got %s", result.Summary.Status)
	}
	if result.Summary.NewCount != 0 || result.Summary.ResolvedCount != 0 {
		t.Error("expected no changes for nil/nil")
	}
}

func TestComputeDiff_SeverityInOutput(t *testing.T) {
	baseline := &ScanFindings{}
	current := &ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Test", Severity: graph.SeverityCritical,
				Affected: []AffectedResource{{Namespace: "ns1", Name: "r1"}}},
		},
	}

	result := ComputeDiff(baseline, current)

	if len(result.NewFindings) != 1 {
		t.Fatalf("expected 1 new finding, got %d", len(result.NewFindings))
	}
	if result.NewFindings[0].Severity != "critical" {
		t.Errorf("expected severity critical, got %s", result.NewFindings[0].Severity)
	}
}
