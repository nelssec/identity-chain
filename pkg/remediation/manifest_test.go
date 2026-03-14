package remediation

import (
	"strings"
	"testing"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func makeRBACFinding(checkID string, severity graph.Severity, ns, name string) analysis.RBACFinding {
	return analysis.RBACFinding{
		CheckID:     checkID,
		Category:    analysis.CategoryOverPermissive,
		Severity:    severity,
		Title:       checkID + " finding",
		Description: "Test finding for " + checkID,
		Affected: []analysis.AffectedResource{
			{Kind: "ClusterRoleBinding", Namespace: ns, Name: name, Details: "test"},
		},
		Remediation: "Fix it",
	}
}

func makePodSecFinding(checkID string, severity graph.Severity, ns, name string) analysis.PodSecurityFinding {
	return analysis.PodSecurityFinding{
		CheckID:     checkID,
		Category:    "container_security",
		Severity:    severity,
		Title:       checkID + " finding",
		Description: "Test finding for " + checkID,
		Affected: []analysis.AffectedWorkload{
			{Kind: "Deployment", Namespace: ns, Name: name, Container: "app", Details: "test"},
		},
		Remediation: "Fix it",
	}
}

func makeNetPolFinding(checkID string, severity graph.Severity, ns, name string) analysis.NetworkPolicyFinding {
	return analysis.NetworkPolicyFinding{
		CheckID:     checkID,
		Category:    "network_exposure",
		Severity:    severity,
		Title:       checkID + " finding",
		Description: "Test finding for " + checkID,
		Affected: []analysis.AffectedNetworkResource{
			{Kind: "Namespace", Namespace: ns, Name: name, Details: "test"},
		},
		Remediation: "Fix it",
	}
}

func TestGenerateDryRunYAML_RBAC(t *testing.T) {
	findings := []analysis.RBACFinding{
		makeRBACFinding("RBAC004", graph.SeverityCritical, "default", "admin-binding"),
	}

	result := GenerateAllRemediations(findings, nil, nil)
	yaml := result.GenerateDryRunYAML()

	if yaml == "" {
		t.Fatal("expected non-empty dry-run YAML for RBAC findings")
	}

	if !strings.Contains(yaml, "# idc:") {
		t.Error("dry-run YAML should contain # idc: traceability comment")
	}

	if !strings.Contains(yaml, "critical") {
		t.Error("dry-run YAML should contain severity")
	}

	if !strings.Contains(yaml, "apiVersion:") {
		t.Error("dry-run YAML should contain actual K8s manifests with apiVersion")
	}
}

func TestGenerateDryRunYAML_NetworkPolicy(t *testing.T) {
	findings := []analysis.NetworkPolicyFinding{
		makeNetPolFinding("NET001", graph.SeverityHigh, "production", "production"),
	}

	result := GenerateAllRemediations(nil, nil, findings)
	yaml := result.GenerateDryRunYAML()

	if yaml == "" {
		t.Fatal("expected non-empty dry-run YAML for network policy findings")
	}

	if !strings.Contains(yaml, "NetworkPolicy") {
		t.Error("dry-run YAML should contain NetworkPolicy resources")
	}

	if !strings.Contains(yaml, "# idc:") {
		t.Error("dry-run YAML should contain # idc: traceability comment")
	}
}

func TestGenerateDryRunYAML_PodSecurity(t *testing.T) {
	findings := []analysis.PodSecurityFinding{
		makePodSecFinding("PSS001", graph.SeverityCritical, "default", "my-deploy"),
	}

	result := GenerateAllRemediations(nil, findings, nil)
	yaml := result.GenerateDryRunYAML()

	if yaml == "" {
		t.Fatal("expected non-empty dry-run YAML for pod security findings")
	}

	if !strings.Contains(yaml, "# idc:") {
		t.Error("dry-run YAML should contain # idc: traceability comment")
	}
}

func TestGenerateDryRunYAML_FindingIDInComment(t *testing.T) {
	findings := []analysis.RBACFinding{
		makeRBACFinding("RBAC004", graph.SeverityCritical, "default", "admin-binding"),
	}

	result := GenerateAllRemediations(findings, nil, nil)
	yaml := result.GenerateDryRunYAML()

	// FindingID format: CheckID-Namespace-Name
	if !strings.Contains(yaml, "# idc: RBAC004-default-admin-binding critical") {
		t.Errorf("expected '# idc: RBAC004-default-admin-binding critical' in YAML, got:\n%s", yaml)
	}
}

func TestGenerateDryRunYAML_SkipsReviewOnlyManifests(t *testing.T) {
	result := &RemediationResult{
		TotalFindings:   2,
		RemediableCount: 2,
		Remediations: []Remediation{
			{
				FindingID: "TEST001-default-test",
				CheckID:   "TEST001",
				Severity:  "high",
				Manifests: []Manifest{
					{
						Action:      "review",
						Description: "Review this manually",
						YAML:        "# This is a review-only comment, not a K8s resource",
					},
				},
			},
			{
				FindingID: "TEST002-default-test",
				CheckID:   "TEST002",
				Severity:  "critical",
				Manifests: []Manifest{
					{
						Action:      "create",
						Description: "Create a role",
						YAML: `apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: test-role
  namespace: default`,
					},
				},
			},
		},
	}

	yaml := result.GenerateDryRunYAML()

	if strings.Contains(yaml, "review-only") {
		t.Error("dry-run YAML should not contain review-only manifests")
	}

	if !strings.Contains(yaml, "TEST002") {
		t.Error("dry-run YAML should contain actionable manifests")
	}

	if strings.Contains(yaml, "TEST001") {
		t.Error("dry-run YAML should not contain review-only finding ID")
	}
}

func TestGenerateCombinedManifests_DeduplicatesManifests(t *testing.T) {
	sharedYAML := `apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny
  namespace: production`

	result := &RemediationResult{
		TotalFindings:   2,
		RemediableCount: 2,
		Remediations: []Remediation{
			{
				FindingID: "NET001-production",
				CheckID:   "NET001",
				Severity:  "high",
				Manifests: []Manifest{
					{Action: "create", Description: "Create default deny", YAML: sharedYAML},
				},
			},
			{
				FindingID: "NET003-production",
				CheckID:   "NET003",
				Severity:  "medium",
				Manifests: []Manifest{
					{Action: "create", Description: "Create default deny", YAML: sharedYAML},
				},
			},
		},
	}

	combined := result.GenerateCombinedManifests()

	count := strings.Count(combined, "default-deny")
	if count != 1 {
		t.Errorf("expected manifest to appear once (deduplication), but appeared %d times", count)
	}

	// Also verify dry-run deduplication
	dryRun := result.GenerateDryRunYAML()
	count = strings.Count(dryRun, "default-deny")
	if count != 1 {
		t.Errorf("expected dry-run manifest to appear once (deduplication), but appeared %d times", count)
	}
}
