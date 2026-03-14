package remediation

import (
	"strings"
	"testing"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestGenerateNetworkPolicyRemediations(t *testing.T) {
	tests := []struct {
		name          string
		findings      []analysis.NetworkPolicyFinding
		wantCount     int
		wantAction    string
		wantCheckID   string
		checkManifest func(t *testing.T, rems []Remediation)
	}{
		{
			name: "no network policy NET001",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:     "NET001",
					Severity:    graph.SeverityHigh,
					Description: "No network policy in namespace",
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "Namespace", Namespace: "default", Name: "default"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Create default-deny network policy",
			wantCheckID: "NET001",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if len(rems[0].Manifests) != 2 {
					t.Fatalf("expected 2 manifests (deny-all + dns), got %d", len(rems[0].Manifests))
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "default-deny-all") {
					t.Error("first manifest should be default-deny-all")
				}
				if !strings.Contains(rems[0].Manifests[1].YAML, "allow-dns-egress") {
					t.Error("second manifest should be allow-dns-egress")
				}
				if rems[0].Resource.Kind != "Namespace" {
					t.Errorf("resource kind should be Namespace, got %s", rems[0].Resource.Kind)
				}
			},
		},
		{
			name: "no default deny NET002",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:     "NET002",
					Severity:    graph.SeverityHigh,
					Description: "No default deny policy",
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "Namespace", Namespace: "production", Name: "production"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Add default-deny network policy",
			wantCheckID: "NET002",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if len(rems[0].Manifests) != 1 {
					t.Fatalf("expected 1 manifest, got %d", len(rems[0].Manifests))
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "default-deny-all") {
					t.Error("should create default-deny-all policy")
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "namespace: production") {
					t.Error("should reference production namespace")
				}
			},
		},
		{
			name: "no ingress policy NET003",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:  "NET003",
					Severity: graph.SeverityMedium,
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "Namespace", Namespace: "staging", Name: "staging"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Add default-deny ingress policy",
			wantCheckID: "NET003",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "default-deny-ingress") {
					t.Error("should create default-deny-ingress")
				}
			},
		},
		{
			name: "no egress policy NET004",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:  "NET004",
					Severity: graph.SeverityMedium,
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "Namespace", Namespace: "dev", Name: "dev"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Add default-deny egress policy",
			wantCheckID: "NET004",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if len(rems[0].Manifests) != 2 {
					t.Fatalf("expected 2 manifests (deny-egress + dns), got %d", len(rems[0].Manifests))
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "default-deny-egress") {
					t.Error("first manifest should be default-deny-egress")
				}
				if !strings.Contains(rems[0].Manifests[1].YAML, "allow-dns-egress") {
					t.Error("second manifest should allow DNS egress")
				}
			},
		},
		{
			name: "allow all ingress NET005",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:     "NET005",
					Severity:    graph.SeverityHigh,
					Description: "Allow-all ingress policy",
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "NetworkPolicy", Namespace: "default", Name: "allow-all"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Restrict overly permissive ingress rules",
			wantCheckID: "NET005",
			checkManifest: func(t *testing.T, rems []Remediation) {
				yaml := rems[0].Manifests[0].YAML
				if !strings.Contains(yaml, "podSelector") {
					t.Error("should suggest podSelector-based ingress")
				}
				if rems[0].Resource.Kind != "NetworkPolicy" {
					t.Errorf("resource kind should be NetworkPolicy, got %s", rems[0].Resource.Kind)
				}
				if rems[0].Manifests[0].Action != "replace" {
					t.Errorf("action should be replace, got %s", rems[0].Manifests[0].Action)
				}
			},
		},
		{
			name: "allow all egress NET006",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:     "NET006",
					Severity:    graph.SeverityHigh,
					Description: "Allow-all egress policy",
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "NetworkPolicy", Namespace: "default", Name: "open-egress"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Restrict overly permissive egress rules",
			wantCheckID: "NET006",
			checkManifest: func(t *testing.T, rems []Remediation) {
				yaml := rems[0].Manifests[0].YAML
				if !strings.Contains(yaml, "port: 5432") {
					t.Error("should suggest specific port restrictions")
				}
			},
		},
		{
			name: "wide CIDR NET007",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:     "NET007",
					Severity:    graph.SeverityMedium,
					Description: "Wide CIDR range",
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "NetworkPolicy", Namespace: "default", Name: "wide-policy"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Replace wide CIDR with specific ranges",
			wantCheckID: "NET007",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "0.0.0.0/0") {
					t.Error("should reference 0.0.0.0/0 as the problem")
				}
			},
		},
		{
			name: "all namespaces NET008",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:     "NET008",
					Severity:    graph.SeverityMedium,
					Description: "All-namespace selector",
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "NetworkPolicy", Namespace: "prod", Name: "ns-wide"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Restrict namespace selector to specific namespaces",
			wantCheckID: "NET008",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "namespaceSelector") {
					t.Error("should reference namespaceSelector")
				}
			},
		},
		{
			name: "unknown check returns nil",
			findings: []analysis.NetworkPolicyFinding{
				{
					CheckID:  "NET999",
					Severity: graph.SeverityLow,
					Affected: []analysis.AffectedNetworkResource{
						{Kind: "NetworkPolicy", Namespace: "default", Name: "unknown"},
					},
				},
			},
			wantCount: 0,
		},
		{
			name:      "empty findings",
			findings:  nil,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rems := GenerateNetworkPolicyRemediations(tt.findings)

			if len(rems) != tt.wantCount {
				t.Fatalf("got %d remediations, want %d", len(rems), tt.wantCount)
			}

			if tt.wantCount == 0 {
				return
			}

			r := rems[0]
			if r.Type != RemediationNetworkPolicy {
				t.Errorf("type = %q, want %q", r.Type, RemediationNetworkPolicy)
			}
			if tt.wantAction != "" && r.Action != tt.wantAction {
				t.Errorf("action = %q, want %q", r.Action, tt.wantAction)
			}
			if tt.wantCheckID != "" && r.CheckID != tt.wantCheckID {
				t.Errorf("checkID = %q, want %q", r.CheckID, tt.wantCheckID)
			}
			if len(r.Manifests) == 0 {
				t.Error("expected at least one manifest")
			}
			for _, m := range r.Manifests {
				if m.YAML == "" {
					t.Error("manifest YAML should not be empty")
				}
			}

			if tt.checkManifest != nil {
				tt.checkManifest(t, rems)
			}
		})
	}
}

func TestGenerateNetworkPolicyRemediations_DeduplicateByNamespace(t *testing.T) {
	// NET001 and NET002 both use nsProcessed to deduplicate per namespace
	findings := []analysis.NetworkPolicyFinding{
		{
			CheckID:  "NET001",
			Severity: graph.SeverityHigh,
			Affected: []analysis.AffectedNetworkResource{
				{Kind: "Namespace", Namespace: "default", Name: "pod1"},
				{Kind: "Namespace", Namespace: "default", Name: "pod2"},
			},
		},
	}

	rems := GenerateNetworkPolicyRemediations(findings)

	// Should only get one remediation since both affected resources are in same namespace
	if len(rems) != 1 {
		t.Errorf("expected 1 remediation (deduplicated by namespace), got %d", len(rems))
	}
}

func TestGenerateNetworkPolicyRemediations_DifferentNamespaces(t *testing.T) {
	findings := []analysis.NetworkPolicyFinding{
		{
			CheckID:  "NET001",
			Severity: graph.SeverityHigh,
			Affected: []analysis.AffectedNetworkResource{
				{Kind: "Namespace", Namespace: "ns1", Name: "ns1"},
				{Kind: "Namespace", Namespace: "ns2", Name: "ns2"},
			},
		},
	}

	rems := GenerateNetworkPolicyRemediations(findings)

	if len(rems) != 2 {
		t.Errorf("expected 2 remediations (different namespaces), got %d", len(rems))
	}
}

func TestGenerateNetworkPolicyRemediations_CrossFindingDedup(t *testing.T) {
	// NET001 and NET002 share the same nsProcessed key pattern
	// If NET001 already processed namespace "default", NET002 should skip it
	findings := []analysis.NetworkPolicyFinding{
		{
			CheckID:  "NET001",
			Severity: graph.SeverityHigh,
			Affected: []analysis.AffectedNetworkResource{
				{Kind: "Namespace", Namespace: "default", Name: "default"},
			},
		},
		{
			CheckID:  "NET002",
			Severity: graph.SeverityHigh,
			Affected: []analysis.AffectedNetworkResource{
				{Kind: "Namespace", Namespace: "default", Name: "default"},
			},
		},
	}

	rems := GenerateNetworkPolicyRemediations(findings)

	// Both NET001 and NET002 use the same "default-default-deny" key,
	// so only one should produce a remediation
	if len(rems) != 1 {
		t.Errorf("expected 1 remediation (cross-finding dedup), got %d", len(rems))
	}
}

func TestGenerateNetworkPolicyRemediations_NET003_Dedup(t *testing.T) {
	findings := []analysis.NetworkPolicyFinding{
		{
			CheckID:  "NET003",
			Severity: graph.SeverityMedium,
			Affected: []analysis.AffectedNetworkResource{
				{Kind: "Namespace", Namespace: "test", Name: "a"},
				{Kind: "Namespace", Namespace: "test", Name: "b"},
			},
		},
	}

	rems := GenerateNetworkPolicyRemediations(findings)
	if len(rems) != 1 {
		t.Errorf("NET003 should dedup by namespace, got %d", len(rems))
	}
}

func TestGenerateNetworkPolicyRemediations_NET004_Dedup(t *testing.T) {
	findings := []analysis.NetworkPolicyFinding{
		{
			CheckID:  "NET004",
			Severity: graph.SeverityMedium,
			Affected: []analysis.AffectedNetworkResource{
				{Kind: "Namespace", Namespace: "test", Name: "a"},
				{Kind: "Namespace", Namespace: "test", Name: "b"},
			},
		},
	}

	rems := GenerateNetworkPolicyRemediations(findings)
	if len(rems) != 1 {
		t.Errorf("NET004 should dedup by namespace, got %d", len(rems))
	}
}

func TestGenerateNetworkPolicyRemediations_MultipleAffectedNET005(t *testing.T) {
	// NET005 does NOT deduplicate - each affected resource gets its own remediation
	findings := []analysis.NetworkPolicyFinding{
		{
			CheckID:  "NET005",
			Severity: graph.SeverityHigh,
			Affected: []analysis.AffectedNetworkResource{
				{Kind: "NetworkPolicy", Namespace: "default", Name: "policy1"},
				{Kind: "NetworkPolicy", Namespace: "default", Name: "policy2"},
			},
		},
	}

	rems := GenerateNetworkPolicyRemediations(findings)
	if len(rems) != 2 {
		t.Errorf("NET005 should not dedup, expected 2 remediations, got %d", len(rems))
	}
}
