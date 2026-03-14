package remediation

import (
	"strings"
	"testing"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestGenerateRBACRemediations(t *testing.T) {
	tests := []struct {
		name          string
		findings      []analysis.RBACFinding
		wantCount     int
		wantType      RemediationType
		wantAction    string
		wantCheckID   string
		checkManifest func(t *testing.T, rems []Remediation)
	}{
		{
			name: "cluster-admin RBAC001 cluster-wide",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC001",
					Severity:    graph.SeverityCritical,
					Description: "Cluster-admin role binding detected",
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRoleBinding", Namespace: "cluster-wide", Name: "admin-binding"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Replace cluster-admin with least-privilege role",
			wantCheckID: "RBAC001",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if len(rems[0].Manifests) != 2 {
					t.Errorf("expected 2 manifests, got %d", len(rems[0].Manifests))
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "ClusterRole") {
					t.Error("cluster-wide should generate ClusterRole")
				}
			},
		},
		{
			name: "cluster-admin RBAC002 namespaced",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC002",
					Severity:    graph.SeverityCritical,
					Description: "Namespaced admin binding",
					Affected: []analysis.AffectedResource{
						{Kind: "RoleBinding", Namespace: "production", Name: "ns-admin"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Replace cluster-admin with least-privilege role",
			wantCheckID: "RBAC002",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "kind: Role") {
					t.Error("namespaced finding should generate Role, not ClusterRole")
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "namespace: production") {
					t.Error("should reference correct namespace")
				}
			},
		},
		{
			name: "secrets access RBAC003",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC003",
					Severity:    graph.SeverityHigh,
					Description: "Role grants secrets access",
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Namespace: "", Name: "secret-reader"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Remove secrets access from role",
			wantCheckID: "RBAC003",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "secret-reader-no-secrets") {
					t.Error("should create role with -no-secrets suffix")
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "ClusterRole") {
					t.Error("empty namespace should generate ClusterRole")
				}
			},
		},
		{
			name: "secrets access RBAC012 namespaced",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC012",
					Severity:    graph.SeverityHigh,
					Description: "Role grants secrets access",
					Affected: []analysis.AffectedResource{
						{Kind: "Role", Namespace: "dev", Name: "dev-role"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Remove secrets access from role",
			wantCheckID: "RBAC012",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "kind: Role") {
					t.Error("namespaced role should generate Role")
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "namespace: dev") {
					t.Error("should reference dev namespace")
				}
			},
		},
		{
			name: "wildcard permissions RBAC004",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC004",
					Severity:    graph.SeverityHigh,
					Description: "Wildcard permissions detected",
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Namespace: "", Name: "wildcard-role"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Replace wildcards with explicit permissions",
			wantCheckID: "RBAC004",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "wildcard-role-explicit") {
					t.Error("should create role with -explicit suffix")
				}
			},
		},
		{
			name: "default service account RBAC005",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC005",
					Severity:    graph.SeverityMedium,
					Description: "Default SA used for workload",
					Affected: []analysis.AffectedResource{
						{Kind: "ServiceAccount", Namespace: "production", Name: "default"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Create dedicated service account for workload",
			wantCheckID: "RBAC005",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "app-service-account") {
					t.Error("should create app-service-account")
				}
				if !strings.Contains(rems[0].Manifests[0].YAML, "automountServiceAccountToken: false") {
					t.Error("should disable automount token")
				}
			},
		},
		{
			name: "default SA with empty namespace defaults to default",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC005",
					Severity:    graph.SeverityMedium,
					Description: "Default SA",
					Affected: []analysis.AffectedResource{
						{Kind: "ServiceAccount", Namespace: "", Name: "default"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Create dedicated service account for workload",
			wantCheckID: "RBAC005",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if rems[0].Resource.Namespace != "default" {
					t.Errorf("empty namespace should default to 'default', got %q", rems[0].Resource.Namespace)
				}
			},
		},
		{
			name: "automount token RBAC006",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC006",
					Severity:    graph.SeverityMedium,
					Description: "Token automount enabled",
					Affected: []analysis.AffectedResource{
						{Kind: "ServiceAccount", Namespace: "kube-system", Name: "monitoring-sa"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationServiceAccount,
			wantAction:  "Disable automatic token mounting",
			wantCheckID: "RBAC006",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "automountServiceAccountToken: false") {
					t.Error("should disable automount")
				}
				if rems[0].Manifests[0].Action != "patch" {
					t.Errorf("action should be patch, got %s", rems[0].Manifests[0].Action)
				}
			},
		},
		{
			name: "pod create access RBAC007",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC007",
					Severity:    graph.SeverityHigh,
					Description: "Pod create permissions",
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Namespace: "", Name: "deployer"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Remove pod creation permissions",
			wantCheckID: "RBAC007",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "deployer-no-pod-create") {
					t.Error("should create role with -no-pod-create suffix")
				}
			},
		},
		{
			name: "escalation permissions RBAC008",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC008",
					Severity:    graph.SeverityCritical,
					Description: "Bind verb on roles",
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Namespace: "", Name: "escalator"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Remove escalation permissions (bind/escalate/impersonate)",
			wantCheckID: "RBAC008",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if rems[0].Manifests[0].Action != "review" {
					t.Errorf("expected review action, got %s", rems[0].Manifests[0].Action)
				}
			},
		},
		{
			name: "escalation RBAC009",
			findings: []analysis.RBACFinding{
				{
					CheckID:  "RBAC009",
					Severity: graph.SeverityCritical,
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Name: "esc-role"},
					},
				},
			},
			wantCount:   1,
			wantCheckID: "RBAC009",
		},
		{
			name: "escalation RBAC010",
			findings: []analysis.RBACFinding{
				{
					CheckID:  "RBAC010",
					Severity: graph.SeverityCritical,
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Name: "imp-role"},
					},
				},
			},
			wantCount:   1,
			wantCheckID: "RBAC010",
		},
		{
			name: "node access RBAC011",
			findings: []analysis.RBACFinding{
				{
					CheckID:     "RBAC011",
					Severity:    graph.SeverityHigh,
					Description: "Node access detected",
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Namespace: "", Name: "node-manager"},
					},
				},
			},
			wantCount:   1,
			wantType:    RemediationRBAC,
			wantAction:  "Restrict node access permissions",
			wantCheckID: "RBAC011",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if rems[0].Manifests[0].Action != "review" {
					t.Errorf("expected review action, got %s", rems[0].Manifests[0].Action)
				}
			},
		},
		{
			name: "escalation RBAC013 and RBAC014",
			findings: []analysis.RBACFinding{
				{
					CheckID:  "RBAC013",
					Severity: graph.SeverityCritical,
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Name: "esc13"},
					},
				},
				{
					CheckID:  "RBAC014",
					Severity: graph.SeverityCritical,
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRole", Name: "esc14"},
					},
				},
			},
			wantCount:   2,
			wantCheckID: "RBAC013",
		},
		{
			name: "wildcard RBAC015",
			findings: []analysis.RBACFinding{
				{
					CheckID:  "RBAC015",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedResource{
						{Kind: "Role", Namespace: "prod", Name: "wide-role"},
					},
				},
			},
			wantCount:   1,
			wantCheckID: "RBAC015",
			wantAction:  "Replace wildcards with explicit permissions",
		},
		{
			name: "unknown check returns nil",
			findings: []analysis.RBACFinding{
				{
					CheckID:  "RBAC999",
					Severity: graph.SeverityLow,
					Affected: []analysis.AffectedResource{
						{Kind: "Role", Namespace: "test", Name: "unknown"},
					},
				},
			},
			wantCount: 0,
		},
		{
			name: "multiple affected resources",
			findings: []analysis.RBACFinding{
				{
					CheckID:  "RBAC001",
					Severity: graph.SeverityCritical,
					Affected: []analysis.AffectedResource{
						{Kind: "ClusterRoleBinding", Namespace: "cluster-wide", Name: "binding1"},
						{Kind: "ClusterRoleBinding", Namespace: "cluster-wide", Name: "binding2"},
					},
				},
			},
			wantCount: 2,
		},
		{
			name:      "empty findings",
			findings:  nil,
			wantCount: 0,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rems := GenerateRBACRemediations(tt.findings)

			if len(rems) != tt.wantCount {
				t.Fatalf("got %d remediations, want %d", len(rems), tt.wantCount)
			}

			if tt.wantCount == 0 {
				return
			}

			r := rems[0]
			if tt.wantType != "" && r.Type != tt.wantType {
				t.Errorf("type = %q, want %q", r.Type, tt.wantType)
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
