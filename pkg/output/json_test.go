package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

// helpers

func makeWorkloadNode(ns, name, kind string) *graph.Node {
	n := graph.NewNode(graph.NodeWorkload, ns, name)
	n.Metadata.WorkloadKind = kind
	return n
}

func makeSANode(ns, name string) *graph.Node {
	return graph.NewNode(graph.NodeServiceAccount, ns, name)
}

func makeResourceNode(ns, name, resourceKind string) *graph.Node {
	n := graph.NewNode(graph.NodeK8sResource, ns, name)
	n.Metadata.ResourceKind = resourceKind
	return n
}

func sampleBlastResult() *analysis.BlastResult {
	return &analysis.BlastResult{
		SourceWorkload: makeWorkloadNode("default", "nginx", "Deployment"),
		ServiceAccount: makeSANode("default", "nginx-sa"),
		K8sResources: []analysis.ResourceAccess{
			{
				Resource: makeResourceNode("default", "secrets", "secrets"),
				Verbs:    []string{"get", "list"},
				ViaRole:  "reader-role",
				Severity: graph.SeverityCritical,
			},
			{
				Resource: makeResourceNode("", "nodes", "nodes"),
				Verbs:    []string{"get"},
				ViaRole:  "node-reader",
				Severity: graph.SeverityLow,
			},
		},
		CloudRoles: []analysis.CloudAccess{
			{
				Provider: "aws",
				RoleARN:  "arn:aws:iam::123456789012:role/my-role",
				Severity: graph.SeverityHigh,
				Policies: []analysis.CloudPolicy{
					{
						Name:    "S3FullAccess",
						IsAdmin: false,
						Actions: []string{"s3:GetObject", "s3:PutObject"},
					},
				},
				BlastRadius: []string{"Read/Write access to S3 buckets"},
			},
		},
		TotalK8sPerms:   3,
		TotalCloudPerms: 1,
		MaxSeverity:     graph.SeverityCritical,
	}
}

// ---------- WriteStats ----------

func TestJSONWriter_WriteStats(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	stats := graph.GraphStats{
		TotalNodes: 10,
		TotalEdges: 15,
		NodeCounts: map[graph.NodeType]int{
			graph.NodeWorkload:       3,
			graph.NodeServiceAccount: 4,
			graph.NodeRole:           3,
		},
		EdgeCounts: map[graph.EdgeType]int{
			graph.EdgeUses:   3,
			graph.EdgeBinds:  4,
			graph.EdgeGrants: 8,
		},
	}

	if err := w.WriteStats(stats); err != nil {
		t.Fatalf("WriteStats error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Fatal("WriteStats produced invalid JSON")
	}

	var decoded graph.GraphStats
	if err := json.Unmarshal(buf.Bytes(), &decoded); err != nil {
		t.Fatalf("cannot unmarshal stats: %v", err)
	}
	if decoded.TotalNodes != 10 {
		t.Errorf("TotalNodes = %d, want 10", decoded.TotalNodes)
	}
	if decoded.TotalEdges != 15 {
		t.Errorf("TotalEdges = %d, want 15", decoded.TotalEdges)
	}
}

// ---------- WriteGraph ----------

func TestJSONWriter_WriteGraph(t *testing.T) {
	g := graph.New()
	n1 := graph.NewNode(graph.NodeWorkload, "default", "web")
	n1.Metadata.WorkloadKind = "Deployment"
	n2 := graph.NewNode(graph.NodeServiceAccount, "default", "web-sa")
	g.AddNode(n1)
	g.AddNode(n2)

	e := graph.NewEdge(graph.EdgeUses, n1.ID, n2.ID)
	g.AddEdge(e)

	var buf bytes.Buffer
	w := NewJSONWriter(&buf)
	if err := w.WriteGraph(g); err != nil {
		t.Fatalf("WriteGraph error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Fatal("WriteGraph produced invalid JSON")
	}

	var raw map[string]json.RawMessage
	json.Unmarshal(buf.Bytes(), &raw)
	for _, key := range []string{"nodes", "edges", "stats"} {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key %q in graph JSON output", key)
		}
	}
}

// ---------- WriteBlastResult ----------

func TestJSONWriter_WriteBlastResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	if err := w.WriteBlastResult(sampleBlastResult()); err != nil {
		t.Fatalf("WriteBlastResult error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Fatal("WriteBlastResult produced invalid JSON")
	}

	var raw map[string]json.RawMessage
	json.Unmarshal(buf.Bytes(), &raw)

	requiredKeys := []string{
		"workload", "service_account", "k8s_resources",
		"cloud_roles", "blast_radius", "total_k8s_permissions",
		"total_cloud_permissions", "max_severity",
	}
	for _, key := range requiredKeys {
		if _, ok := raw[key]; !ok {
			t.Errorf("missing key %q in blast result JSON", key)
		}
	}
}

// ---------- WriteBlastResults ----------

func TestJSONWriter_WriteBlastResults(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	results := []*analysis.BlastResult{sampleBlastResult()}
	if err := w.WriteBlastResults(results); err != nil {
		t.Fatalf("WriteBlastResults error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Fatal("WriteBlastResults produced invalid JSON")
	}

	var arr []json.RawMessage
	json.Unmarshal(buf.Bytes(), &arr)
	if len(arr) != 1 {
		t.Errorf("expected 1 element, got %d", len(arr))
	}
}

func TestJSONWriter_WriteBlastResults_Empty(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	if err := w.WriteBlastResults(nil); err != nil {
		t.Fatalf("WriteBlastResults error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("invalid JSON for empty blast results")
	}
}

// ---------- WriteRBACAuditResult ----------

func TestJSONWriter_WriteRBACAuditResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	result := &analysis.RBACAuditResult{
		Findings: []analysis.RBACFinding{
			{
				CheckID:     "RBAC001",
				Category:    analysis.CategoryPrivilegeEscalation,
				Severity:    graph.SeverityCritical,
				Title:       "Wildcard permissions",
				Description: "ServiceAccount has wildcard permissions",
				Affected: []analysis.AffectedResource{
					{Kind: "ServiceAccount", Namespace: "default", Name: "admin-sa", Details: "has * verbs"},
				},
				Remediation: "Restrict verbs to specific actions",
			},
		},
		Summary: analysis.AuditSummary{
			Critical: 1,
		},
		ChecksRun:     []string{"RBAC001"},
		TotalFindings: 1,
	}

	if err := w.WriteRBACAuditResult(result); err != nil {
		t.Fatalf("WriteRBACAuditResult error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Fatal("invalid JSON")
	}

	out := buf.String()
	if !strings.Contains(out, "RBAC001") {
		t.Error("output should contain check ID RBAC001")
	}
}

// ---------- WritePodSecurityResult ----------

func TestJSONWriter_WritePodSecurityResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	result := &analysis.PodSecurityResult{
		Findings: []analysis.PodSecurityFinding{
			{
				CheckID:     "PSS001",
				Category:    "privilege_escalation",
				Severity:    graph.SeverityCritical,
				Title:       "Privileged Containers",
				Description: "Container running in privileged mode",
				Affected: []analysis.AffectedWorkload{
					{Kind: "Deployment", Namespace: "default", Name: "web", Container: "app", Details: "privileged: true"},
				},
				Remediation: "Remove privileged: true",
			},
		},
		Summary: analysis.PodSecuritySummary{
			Critical:   1,
			ByCategory: map[string]int{"privilege_escalation": 1},
		},
		ChecksRun:    []string{"PSS001"},
		TotalFindings: 1,
	}

	if err := w.WritePodSecurityResult(result); err != nil {
		t.Fatalf("WritePodSecurityResult error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("invalid JSON")
	}
	if !strings.Contains(buf.String(), "PSS001") {
		t.Error("output should contain PSS001")
	}
}

// ---------- WriteNetworkPolicyResult ----------

func TestJSONWriter_WriteNetworkPolicyResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	result := &analysis.NetworkPolicyResult{
		Findings: []analysis.NetworkPolicyFinding{
			{
				CheckID:     "NET001",
				Category:    "missing_policy",
				Severity:    graph.SeverityHigh,
				Title:       "No Network Policy",
				Description: "Workload has no network policy",
				Affected: []analysis.AffectedNetworkResource{
					{Kind: "Deployment", Namespace: "default", Name: "web", Details: "no policy", Services: []string{"web-svc"}},
				},
				Remediation: "Create NetworkPolicy",
			},
		},
		Summary: analysis.NetworkPolicySummary{
			High:                   1,
			TotalNetworkPolicies:   2,
			WorkloadsWithoutPolicy: 1,
			ByCategory:            map[string]int{"missing_policy": 1},
		},
		ChecksRun:    []string{"NET001"},
		TotalFindings: 1,
	}

	if err := w.WriteNetworkPolicyResult(result); err != nil {
		t.Fatalf("WriteNetworkPolicyResult error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("invalid JSON")
	}
	if !strings.Contains(buf.String(), "NET001") {
		t.Error("output should contain NET001")
	}
}

// ---------- convertBlastResult ----------

func TestConvertBlastResult_NilFields(t *testing.T) {
	r := &analysis.BlastResult{
		TotalK8sPerms: 0,
		MaxSeverity:   graph.SeverityLow,
	}
	result := convertBlastResult(r)
	if result.Workload != nil {
		t.Error("expected nil workload")
	}
	if result.ServiceAccount != nil {
		t.Error("expected nil service account")
	}
	if result.TotalK8sPerms != 0 {
		t.Errorf("expected 0 perms, got %d", result.TotalK8sPerms)
	}
}

func TestConvertBlastResult_WithData(t *testing.T) {
	r := sampleBlastResult()
	result := convertBlastResult(r)

	if result.Workload == nil {
		t.Fatal("workload should not be nil")
	}
	if result.Workload.Name != "nginx" {
		t.Errorf("workload name = %q, want %q", result.Workload.Name, "nginx")
	}
	if result.Workload.Kind != "Deployment" {
		t.Errorf("workload kind = %q, want %q", result.Workload.Kind, "Deployment")
	}
	if result.ServiceAccount == nil {
		t.Fatal("service account should not be nil")
	}
	if result.ServiceAccount.Name != "nginx-sa" {
		t.Errorf("sa name = %q, want %q", result.ServiceAccount.Name, "nginx-sa")
	}
	if len(result.K8sResources) != 2 {
		t.Errorf("expected 2 k8s resources, got %d", len(result.K8sResources))
	}
	if len(result.CloudRoles) != 1 {
		t.Errorf("expected 1 cloud role, got %d", len(result.CloudRoles))
	}
	if result.MaxSeverity != graph.SeverityCritical {
		t.Errorf("max severity = %q, want %q", result.MaxSeverity, graph.SeverityCritical)
	}
}

// ---------- describeK8sBlastRadius ----------

func TestDescribeK8sBlastRadius_Secrets(t *testing.T) {
	tests := []struct {
		name     string
		resource string
		ns       string
		verbs    []string
		severity graph.Severity
		contains string
	}{
		{"secrets read", "secrets", "default", []string{"get", "list"}, graph.SeverityCritical, "READ ALL SECRETS"},
		{"secrets wildcard", "secrets", "", []string{"*"}, graph.SeverityCritical, "READ ALL SECRETS"},
		{"secrets write only", "secrets", "kube-system", []string{"create"}, graph.SeverityHigh, "access to secrets"},
		{"pods write", "pods", "default", []string{"create"}, graph.SeverityHigh, "CREATE/MODIFY PODS"},
		{"pods read", "pods", "ns1", []string{"get"}, graph.SeverityLow, "Read access to pods"},
		{"pods/exec", "pods/exec", "default", []string{"create"}, graph.SeverityHigh, "EXEC INTO PODS"},
		{"deployments write", "deployments", "default", []string{"update"}, graph.SeverityHigh, "modify deployments"},
		{"roles write", "roles", "", []string{"create"}, graph.SeverityCritical, "MODIFY RBAC"},
		{"nodes write", "nodes", "", []string{"update"}, graph.SeverityHigh, "modify NODES"},
		{"nodes read", "nodes", "", []string{"get"}, graph.SeverityLow, "access to nodes"},
		{"custom critical", "custom-resource", "ns1", []string{"get"}, graph.SeverityCritical, "CRITICAL"},
		{"custom low", "configmaps", "ns1", []string{"get"}, graph.SeverityLow, "access to configmaps"},
		{"cluster wide scope", "secrets", "", []string{"get"}, graph.SeverityCritical, "cluster-wide"},
		{"full control wildcard", "pods", "ns1", []string{"*"}, graph.SeverityHigh, "CREATE/MODIFY PODS"},
	}

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got := describeK8sBlastRadius(tc.resource, tc.ns, tc.verbs, tc.severity)
			if !strings.Contains(got, tc.contains) {
				t.Errorf("describeK8sBlastRadius(%q, %q, %v, %q) = %q, want to contain %q",
					tc.resource, tc.ns, tc.verbs, tc.severity, got, tc.contains)
			}
		})
	}
}

func TestDescribeK8sBlastRadius_ReadWriteDelete(t *testing.T) {
	got := describeK8sBlastRadius("configmaps", "default", []string{"get", "create", "delete"}, graph.SeverityMedium)
	if !strings.Contains(got, "Read/Write/Delete") {
		t.Errorf("expected Read/Write/Delete, got %q", got)
	}
}

func TestDescribeK8sBlastRadius_ReadDelete(t *testing.T) {
	got := describeK8sBlastRadius("configmaps", "default", []string{"get", "delete"}, graph.SeverityMedium)
	if !strings.Contains(got, "Read/Delete") {
		t.Errorf("expected Read/Delete, got %q", got)
	}
}

// ---------- WriteCloudAuditResult ----------

func TestJSONWriter_WriteCloudAuditResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewJSONWriter(&buf)

	result := &analysis.CloudIAMAuditResult{
		Findings: []analysis.CloudIAMFinding{
			{
				Provider:    "aws",
				Category:    analysis.CloudCategoryAdminAccess,
				Severity:    graph.SeverityCritical,
				Title:       "Admin policy attached",
				Description: "Role has AdministratorAccess policy",
				RoleARN:     "arn:aws:iam::123456789012:role/admin-role",
				Remediation: "Remove admin policy",
			},
		},
		Summary: analysis.CloudIAMSummary{
			Critical:   1,
			ByProvider: map[string]int{"aws": 1},
		},
		AnalyzedRoles: 5,
	}

	if err := w.WriteCloudAuditResult(result); err != nil {
		t.Fatalf("WriteCloudAuditResult error: %v", err)
	}
	if !json.Valid(buf.Bytes()) {
		t.Fatal("invalid JSON")
	}
}
