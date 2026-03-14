package output

import (
	"bytes"
	"strings"
	"testing"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

// ---------- WriteStats ----------

func TestTableWriter_WriteStats(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)

	stats := graph.GraphStats{
		TotalNodes: 8,
		TotalEdges: 12,
		NodeCounts: map[graph.NodeType]int{
			graph.NodeWorkload:       2,
			graph.NodeServiceAccount: 3,
			graph.NodeRole:           3,
		},
		EdgeCounts: map[graph.EdgeType]int{
			graph.EdgeUses:   2,
			graph.EdgeBinds:  3,
			graph.EdgeGrants: 7,
		},
	}

	if err := w.WriteStats(stats); err != nil {
		t.Fatalf("WriteStats error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Graph Statistics",
		"Total Nodes: 8",
		"Total Edges: 12",
		"Node Counts:",
		"Edge Counts:",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

// ---------- WriteGraph ----------

func TestTableWriter_WriteGraph(t *testing.T) {
	g := graph.New()
	n1 := graph.NewNode(graph.NodeWorkload, "default", "app")
	n1.Metadata.WorkloadKind = "Deployment"
	n2 := graph.NewNode(graph.NodeServiceAccount, "default", "app-sa")
	g.AddNode(n1)
	g.AddNode(n2)
	g.AddEdge(graph.NewEdge(graph.EdgeUses, n1.ID, n2.ID))

	var buf bytes.Buffer
	w := NewTableWriter(&buf)
	if err := w.WriteGraph(g); err != nil {
		t.Fatalf("WriteGraph error: %v", err)
	}

	out := buf.String()
	if !strings.Contains(out, "Total Nodes: 2") {
		t.Errorf("expected Total Nodes: 2, got:\n%s", out)
	}
	if !strings.Contains(out, "Total Edges: 1") {
		t.Errorf("expected Total Edges: 1, got:\n%s", out)
	}
}

// ---------- WriteBlastResult ----------

func TestTableWriter_WriteBlastResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)

	r := sampleBlastResult()
	if err := w.WriteBlastResult(r); err != nil {
		t.Fatalf("WriteBlastResult error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Blast Radius Analysis",
		"nginx",
		"nginx-sa",
		"K8s Permissions: 3",
		"Cloud Roles:     1",
		"Kubernetes Resource Access",
		"reader-role",
		"Cloud Role Access",
		"aws",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestTableWriter_WriteBlastResult_Nil(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)
	if err := w.WriteBlastResult(nil); err != nil {
		t.Fatalf("WriteBlastResult(nil) error: %v", err)
	}
	if !strings.Contains(buf.String(), "No results found") {
		t.Error("expected 'No results found' for nil input")
	}
}

func TestTableWriter_WriteBlastResult_NoK8sResources(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)

	r := &analysis.BlastResult{
		SourceWorkload: makeWorkloadNode("ns", "app", "Deployment"),
		ServiceAccount: makeSANode("ns", "app-sa"),
		TotalK8sPerms:  0,
		MaxSeverity:    graph.SeverityLow,
	}
	if err := w.WriteBlastResult(r); err != nil {
		t.Fatalf("error: %v", err)
	}
	out := buf.String()
	if strings.Contains(out, "Kubernetes Resource Access") {
		t.Error("should not show K8s resource table when empty")
	}
}

// ---------- WriteBlastResults ----------

func TestTableWriter_WriteBlastResults(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)

	results := []*analysis.BlastResult{sampleBlastResult()}
	if err := w.WriteBlastResults(results); err != nil {
		t.Fatalf("WriteBlastResults error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Workload Blast Radius Summary",
		"WORKLOAD",
		"NAMESPACE",
		"SERVICE ACCOUNT",
		"Total: 1 workloads",
		"Critical: 1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestTableWriter_WriteBlastResults_Empty(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)
	if err := w.WriteBlastResults(nil); err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(buf.String(), "No workloads found") {
		t.Error("expected 'No workloads found'")
	}
}

// ---------- WriteRBACAuditResult ----------

func TestTableWriter_WriteRBACAuditResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)

	result := &analysis.RBACAuditResult{
		Findings: []analysis.RBACFinding{
			{
				CheckID:     "RBAC001",
				Severity:    graph.SeverityCritical,
				Title:       "Wildcard permissions",
				Description: "SA has wildcard",
				Affected: []analysis.AffectedResource{
					{Namespace: "default", Name: "admin-sa", Details: "has *"},
				},
				Remediation: "Restrict verbs",
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

	out := buf.String()
	for _, want := range []string{
		"RBAC Security Audit",
		"RBAC001",
		"Wildcard permissions",
		"Critical: 1",
		"Remediation: Restrict verbs",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestTableWriter_WriteRBACAuditResult_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)

	result := &analysis.RBACAuditResult{
		ChecksRun:     []string{"RBAC001"},
		TotalFindings: 0,
	}

	if err := w.WriteRBACAuditResult(result); err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(buf.String(), "No security issues found") {
		t.Error("expected 'No security issues found'")
	}
}

// ---------- WritePodSecurityResult ----------

func TestTableWriter_WritePodSecurityResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)

	result := &analysis.PodSecurityResult{
		Findings: []analysis.PodSecurityFinding{
			{
				CheckID:     "PSS001",
				Severity:    graph.SeverityCritical,
				Title:       "Privileged Containers",
				Description: "Running privileged",
				Affected: []analysis.AffectedWorkload{
					{Kind: "Deployment", Namespace: "default", Name: "web", Container: "app", Details: "privileged: true"},
				},
				Remediation: "Remove privileged",
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

	out := buf.String()
	for _, want := range []string{
		"Pod Security Audit",
		"PSS001",
		"Privileged Containers",
		"Deployment default/web/app",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestTableWriter_WritePodSecurityResult_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)
	result := &analysis.PodSecurityResult{
		ChecksRun:    []string{"PSS001"},
		TotalFindings: 0,
	}
	if err := w.WritePodSecurityResult(result); err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(buf.String(), "No pod security issues found") {
		t.Error("expected 'No pod security issues found'")
	}
}

// ---------- WriteNetworkPolicyResult ----------

func TestTableWriter_WriteNetworkPolicyResult(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)

	result := &analysis.NetworkPolicyResult{
		Findings: []analysis.NetworkPolicyFinding{
			{
				CheckID:     "NET001",
				Severity:    graph.SeverityHigh,
				Title:       "No Network Policy",
				Description: "Workload has no policy",
				Affected: []analysis.AffectedNetworkResource{
					{Kind: "Deployment", Namespace: "default", Name: "web", Details: "no policy", Services: []string{"web-svc"}},
				},
				Remediation: "Create NetworkPolicy",
			},
		},
		Summary: analysis.NetworkPolicySummary{
			High:                   1,
			TotalNetworkPolicies:   0,
			WorkloadsWithoutPolicy: 1,
			ByCategory:            map[string]int{"missing_policy": 1},
		},
		ChecksRun:    []string{"NET001"},
		TotalFindings: 1,
	}

	if err := w.WriteNetworkPolicyResult(result); err != nil {
		t.Fatalf("WriteNetworkPolicyResult error: %v", err)
	}

	out := buf.String()
	for _, want := range []string{
		"Network Policy Audit",
		"NET001",
		"No Network Policy",
		"web-svc",
		"Workloads without policy:     1",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q", want)
		}
	}
}

func TestTableWriter_WriteNetworkPolicyResult_NoFindings(t *testing.T) {
	var buf bytes.Buffer
	w := NewTableWriter(&buf)
	result := &analysis.NetworkPolicyResult{
		ChecksRun:    []string{"NET001"},
		TotalFindings: 0,
		Summary: analysis.NetworkPolicySummary{
			TotalNetworkPolicies: 5,
		},
	}
	if err := w.WriteNetworkPolicyResult(result); err != nil {
		t.Fatalf("error: %v", err)
	}
	if !strings.Contains(buf.String(), "No network policy issues found") {
		t.Error("expected 'No network policy issues found'")
	}
}

// ---------- severityColor ----------

func TestSeverityColor(t *testing.T) {
	tests := []struct {
		severity graph.Severity
		contains string
	}{
		{graph.SeverityCritical, "\033[31m"},
		{graph.SeverityHigh, "\033[33m"},
		{graph.SeverityMedium, "\033[36m"},
		{graph.SeverityLow, "low"},
	}
	for _, tc := range tests {
		got := severityColor(tc.severity)
		if !strings.Contains(got, tc.contains) {
			t.Errorf("severityColor(%q) = %q, want to contain %q", tc.severity, got, tc.contains)
		}
	}
}

// ---------- truncateString ----------

func TestTruncateString(t *testing.T) {
	if got := truncateString("short", 10); got != "short" {
		t.Errorf("expected %q, got %q", "short", got)
	}
	if got := truncateString("a-very-long-string-here", 10); got != "a-very-l.." {
		t.Errorf("expected %q, got %q", "a-very-l..", got)
	}
	if got := truncateString("exact", 5); got != "exact" {
		t.Errorf("expected %q, got %q", "exact", got)
	}
}
