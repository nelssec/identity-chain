package output

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestSARIFWriter_WriteCombinedResults_AllNil(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf, "0.1.0")

	if err := w.WriteCombinedResults(nil, nil, nil, nil); err != nil {
		t.Fatalf("error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Fatal("invalid JSON")
	}

	var doc sarifDocument
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}

	if doc.Version != "2.1.0" {
		t.Errorf("version = %q, want %q", doc.Version, "2.1.0")
	}
	if len(doc.Runs) != 1 {
		t.Fatalf("expected 1 run, got %d", len(doc.Runs))
	}
	if len(doc.Runs[0].Results) != 0 {
		t.Errorf("expected 0 results, got %d", len(doc.Runs[0].Results))
	}
	if doc.Runs[0].Tool.Driver.Name != "identity-chain" {
		t.Errorf("tool name = %q, want %q", doc.Runs[0].Tool.Driver.Name, "identity-chain")
	}
	if doc.Runs[0].Tool.Driver.Version != "0.1.0" {
		t.Errorf("tool version = %q, want %q", doc.Runs[0].Tool.Driver.Version, "0.1.0")
	}
}

func TestSARIFWriter_WriteCombinedResults_WithFindings(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf, "1.0.0")

	rbac := &analysis.RBACAuditResult{
		Findings: []analysis.RBACFinding{
			{
				CheckID:     "RBAC001",
				Severity:    graph.SeverityCritical,
				Title:       "Wildcard",
				Description: "SA has wildcard",
			},
		},
	}

	podSec := &analysis.PodSecurityResult{
		Findings: []analysis.PodSecurityFinding{
			{
				CheckID:     "PSS001",
				Severity:    graph.SeverityHigh,
				Title:       "Privileged",
				Description: "Container is privileged",
			},
		},
	}

	netPol := &analysis.NetworkPolicyResult{
		Findings: []analysis.NetworkPolicyFinding{
			{
				CheckID:     "NET001",
				Severity:    graph.SeverityMedium,
				Title:       "No policy",
				Description: "Missing network policy",
			},
		},
	}

	cloud := &analysis.CloudIAMAuditResult{
		Findings: []analysis.CloudIAMFinding{
			{
				Category:    analysis.CloudCategoryAdminAccess,
				Severity:    graph.SeverityLow,
				Title:       "Unused role",
				Description: "Role not in use",
			},
		},
	}

	if err := w.WriteCombinedResults(rbac, podSec, netPol, cloud); err != nil {
		t.Fatalf("error: %v", err)
	}

	if !json.Valid(buf.Bytes()) {
		t.Fatal("invalid JSON")
	}

	var doc sarifDocument
	json.Unmarshal(buf.Bytes(), &doc)

	if len(doc.Runs[0].Results) != 4 {
		t.Fatalf("expected 4 results, got %d", len(doc.Runs[0].Results))
	}

	// Verify each finding mapped correctly
	r0 := doc.Runs[0].Results[0]
	if r0.RuleID != "RBAC001" {
		t.Errorf("result[0].ruleId = %q, want RBAC001", r0.RuleID)
	}
	if r0.Level != "error" {
		t.Errorf("critical severity should map to 'error', got %q", r0.Level)
	}
	if r0.Kind != "fail" {
		t.Errorf("kind should be 'fail', got %q", r0.Kind)
	}

	r1 := doc.Runs[0].Results[1]
	if r1.Level != "error" {
		t.Errorf("high severity should map to 'error', got %q", r1.Level)
	}

	r2 := doc.Runs[0].Results[2]
	if r2.Level != "warning" {
		t.Errorf("medium severity should map to 'warning', got %q", r2.Level)
	}

	r3 := doc.Runs[0].Results[3]
	if r3.Level != "note" {
		t.Errorf("low severity should map to 'note', got %q", r3.Level)
	}

	// Cloud finding ruleId should be the category string
	if r3.RuleID != string(analysis.CloudCategoryAdminAccess) {
		t.Errorf("cloud finding ruleId = %q, want %q", r3.RuleID, string(analysis.CloudCategoryAdminAccess))
	}
}

func TestSARIFWriter_WriteCombinedResults_MessageFormat(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf, "1.0.0")

	rbac := &analysis.RBACAuditResult{
		Findings: []analysis.RBACFinding{
			{
				CheckID:     "RBAC002",
				Severity:    graph.SeverityHigh,
				Title:       "Over-permissive",
				Description: "Too many permissions",
			},
		},
	}

	w.WriteCombinedResults(rbac, nil, nil, nil)

	out := buf.String()
	// Message should be "Title: Description"
	if !strings.Contains(out, "Over-permissive: Too many permissions") {
		t.Errorf("message should contain 'Title: Description', got:\n%s", out)
	}
}

func TestSARIFWriter_SchemaURI(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf, "1.0.0")
	w.WriteCombinedResults(nil, nil, nil, nil)

	var doc sarifDocument
	json.Unmarshal(buf.Bytes(), &doc)

	if doc.Schema != "https://schemastore.azurewebsites.net/schemas/json/sarif-2.1.0.json" {
		t.Errorf("unexpected schema URI: %q", doc.Schema)
	}
}

func TestSARIFWriter_InformationURI(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf, "1.0.0")
	w.WriteCombinedResults(nil, nil, nil, nil)

	var doc sarifDocument
	json.Unmarshal(buf.Bytes(), &doc)

	if doc.Runs[0].Tool.Driver.InformationURI != "https://github.com/nelssec/identity-chain" {
		t.Errorf("unexpected informationUri: %q", doc.Runs[0].Tool.Driver.InformationURI)
	}
}

// ---------- severityToSARIFLevel ----------

func TestSeverityToSARIFLevel(t *testing.T) {
	tests := []struct {
		input string
		want  string
	}{
		{"critical", "error"},
		{"high", "error"},
		{"medium", "warning"},
		{"low", "note"},
		{"info", "none"},
		{"", "none"},
		{"unknown", "none"},
	}
	for _, tc := range tests {
		got := severityToSARIFLevel(tc.input)
		if got != tc.want {
			t.Errorf("severityToSARIFLevel(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestSARIFWriter_PartialNilInputs(t *testing.T) {
	var buf bytes.Buffer
	w := NewSARIFWriter(&buf, "0.2.0")

	rbac := &analysis.RBACAuditResult{
		Findings: []analysis.RBACFinding{
			{CheckID: "RBAC010", Severity: graph.SeverityMedium, Title: "Test", Description: "desc"},
		},
	}

	if err := w.WriteCombinedResults(rbac, nil, nil, nil); err != nil {
		t.Fatalf("error: %v", err)
	}

	var doc sarifDocument
	json.Unmarshal(buf.Bytes(), &doc)

	if len(doc.Runs[0].Results) != 1 {
		t.Errorf("expected 1 result, got %d", len(doc.Runs[0].Results))
	}
}
