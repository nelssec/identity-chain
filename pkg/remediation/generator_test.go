package remediation

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestGenerateAllRemediations_MixedFindings(t *testing.T) {
	rbac := []analysis.RBACFinding{
		{
			CheckID:     "RBAC001",
			Severity:    graph.SeverityCritical,
			Description: "Cluster-admin binding found",
			Affected: []analysis.AffectedResource{
				{Kind: "ClusterRoleBinding", Namespace: "cluster-wide", Name: "admin-binding"},
			},
		},
	}
	podSec := []analysis.PodSecurityFinding{
		{
			CheckID:     "PSS001",
			Severity:    graph.SeverityCritical,
			Description: "Privileged container",
			Affected: []analysis.AffectedWorkload{
				{Kind: "Deployment", Namespace: "default", Name: "web-app", Container: "nginx"},
			},
		},
	}
	netPol := []analysis.NetworkPolicyFinding{
		{
			CheckID:     "NET001",
			Severity:    graph.SeverityHigh,
			Description: "No network policy",
			Affected: []analysis.AffectedNetworkResource{
				{Kind: "Namespace", Namespace: "default", Name: "default"},
			},
		},
	}

	result := GenerateAllRemediations(rbac, podSec, netPol)

	if result.TotalFindings != 3 {
		t.Errorf("TotalFindings = %d, want 3", result.TotalFindings)
	}
	if result.RemediableCount == 0 {
		t.Error("expected at least some remediable findings")
	}
	if result.CombinedManifests == "" {
		t.Error("CombinedManifests should not be empty")
	}

	// Check that we have remediations from all three types
	typesSeen := map[RemediationType]bool{}
	for _, r := range result.Remediations {
		typesSeen[r.Type] = true
	}
	if !typesSeen[RemediationRBAC] {
		t.Error("expected RBAC remediations")
	}
	if !typesSeen[RemediationPodSecurity] {
		t.Error("expected PodSecurity remediations")
	}
	if !typesSeen[RemediationNetworkPolicy] {
		t.Error("expected NetworkPolicy remediations")
	}
}

func TestGenerateAllRemediations_EmptyFindings(t *testing.T) {
	result := GenerateAllRemediations(nil, nil, nil)

	if result.TotalFindings != 0 {
		t.Errorf("TotalFindings = %d, want 0", result.TotalFindings)
	}
	if result.RemediableCount != 0 {
		t.Errorf("RemediableCount = %d, want 0", result.RemediableCount)
	}
	if len(result.Remediations) != 0 {
		t.Errorf("expected no remediations, got %d", len(result.Remediations))
	}
}

func TestFilterBySeverity(t *testing.T) {
	result := &RemediationResult{
		TotalFindings: 4,
		Remediations: []Remediation{
			{Type: RemediationRBAC, Severity: "critical", CheckID: "RBAC001", Manifests: []Manifest{{Action: "create", YAML: "a"}}},
			{Type: RemediationRBAC, Severity: "high", CheckID: "RBAC003", Manifests: []Manifest{{Action: "create", YAML: "b"}}},
			{Type: RemediationPodSecurity, Severity: "medium", CheckID: "PSS001", Manifests: []Manifest{{Action: "patch", YAML: "c"}}},
			{Type: RemediationNetworkPolicy, Severity: "low", CheckID: "NET001", Manifests: []Manifest{{Action: "create", YAML: "d"}}},
		},
	}

	tests := []struct {
		name        string
		minSeverity string
		wantCount   int
	}{
		{"filter critical only", "critical", 1},
		{"filter high and above", "high", 2},
		{"filter medium and above", "medium", 3},
		{"filter low and above", "low", 4},
		{"filter info (all)", "info", 4},
		{"unknown severity defaults to medium", "unknown", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterBySeverity(result, tt.minSeverity)
			if filtered.RemediableCount != tt.wantCount {
				t.Errorf("FilterBySeverity(%q) got %d remediations, want %d",
					tt.minSeverity, filtered.RemediableCount, tt.wantCount)
			}
			if filtered.TotalFindings != result.TotalFindings {
				t.Error("TotalFindings should be preserved from original")
			}
		})
	}
}

func TestFilterByType(t *testing.T) {
	result := &RemediationResult{
		TotalFindings: 5,
		Remediations: []Remediation{
			{Type: RemediationRBAC, Severity: "high", Manifests: []Manifest{{Action: "create", YAML: "a"}}},
			{Type: RemediationRBAC, Severity: "critical", Manifests: []Manifest{{Action: "create", YAML: "b"}}},
			{Type: RemediationPodSecurity, Severity: "high", Manifests: []Manifest{{Action: "patch", YAML: "c"}}},
			{Type: RemediationNetworkPolicy, Severity: "medium", Manifests: []Manifest{{Action: "create", YAML: "d"}}},
			{Type: RemediationServiceAccount, Severity: "medium", Manifests: []Manifest{{Action: "patch", YAML: "e"}}},
		},
	}

	tests := []struct {
		name      string
		remType   RemediationType
		wantCount int
	}{
		{"filter RBAC", RemediationRBAC, 2},
		{"filter PodSecurity", RemediationPodSecurity, 1},
		{"filter NetworkPolicy", RemediationNetworkPolicy, 1},
		{"filter ServiceAccount", RemediationServiceAccount, 1},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterByType(result, tt.remType)
			if filtered.RemediableCount != tt.wantCount {
				t.Errorf("FilterByType(%q) got %d, want %d",
					tt.remType, filtered.RemediableCount, tt.wantCount)
			}
		})
	}
}

func TestFilterByNamespace(t *testing.T) {
	result := &RemediationResult{
		TotalFindings:   3,
		RemediableCount: 3,
		Remediations: []Remediation{
			{Type: RemediationRBAC, Resource: ResourceRef{Namespace: "default"}, Manifests: []Manifest{{Action: "create", YAML: "a"}}},
			{Type: RemediationRBAC, Resource: ResourceRef{Namespace: "kube-system"}, Manifests: []Manifest{{Action: "create", YAML: "b"}}},
			{Type: RemediationPodSecurity, Resource: ResourceRef{Namespace: "default"}, Manifests: []Manifest{{Action: "patch", YAML: "c"}}},
		},
	}

	tests := []struct {
		name      string
		namespace string
		wantCount int
	}{
		{"filter default namespace", "default", 2},
		{"filter kube-system", "kube-system", 1},
		{"filter nonexistent namespace", "staging", 0},
		{"empty namespace returns all", "", 3},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			filtered := FilterByNamespace(result, tt.namespace)
			if filtered.RemediableCount != tt.wantCount {
				t.Errorf("FilterByNamespace(%q) got %d, want %d",
					tt.namespace, filtered.RemediableCount, tt.wantCount)
			}
		})
	}
}
