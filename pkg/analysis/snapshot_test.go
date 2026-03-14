package analysis

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestSnapshotRoundtrip(t *testing.T) {
	findings := ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Wildcard verbs", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "default", Name: "admin"}}},
		},
		PodSecFindings: []PodSecurityFinding{
			{CheckID: "PSS001", Title: "Privileged container", Severity: graph.SeverityCritical,
				Affected: []AffectedWorkload{{Namespace: "kube-system", Name: "debug-pod"}}},
		},
		NetPolFindings: []NetworkPolicyFinding{
			{CheckID: "NET001", Title: "Missing network policy", Severity: graph.SeverityMedium,
				Affected: []AffectedNetworkResource{{Namespace: "prod", Name: "api-svc"}}},
		},
		CloudFindings: []CloudIAMFinding{
			{Title: "Admin role", Provider: "aws", Category: CloudCategoryAdminAccess,
				Severity: graph.SeverityCritical, RoleARN: "arn:aws:iam::123:role/admin"},
		},
	}

	stats := &SnapshotGraphStats{
		TotalNodes:    42,
		TotalEdges:    67,
		WorkloadCount: 10,
		SACount:       8,
		RoleCount:     15,
	}

	snap := NewSnapshot(findings, stats)

	if snap.Version != SnapshotVersion {
		t.Errorf("expected version %s, got %s", SnapshotVersion, snap.Version)
	}
	if snap.Timestamp == "" {
		t.Error("expected non-empty timestamp")
	}

	// Write to temp file
	dir := t.TempDir()
	path := filepath.Join(dir, "snapshot.json")

	if err := WriteSnapshot(snap, path); err != nil {
		t.Fatalf("WriteSnapshot failed: %v", err)
	}

	// Read back
	loaded, err := LoadScanFindings(path)
	if err != nil {
		t.Fatalf("LoadScanFindings failed: %v", err)
	}

	if len(loaded.RBACFindings) != 1 {
		t.Errorf("expected 1 RBAC finding, got %d", len(loaded.RBACFindings))
	}
	if loaded.RBACFindings[0].CheckID != "RBAC001" {
		t.Errorf("expected RBAC001, got %s", loaded.RBACFindings[0].CheckID)
	}
	if len(loaded.PodSecFindings) != 1 {
		t.Errorf("expected 1 PodSec finding, got %d", len(loaded.PodSecFindings))
	}
	if len(loaded.NetPolFindings) != 1 {
		t.Errorf("expected 1 NetPol finding, got %d", len(loaded.NetPolFindings))
	}
	if len(loaded.CloudFindings) != 1 {
		t.Errorf("expected 1 Cloud finding, got %d", len(loaded.CloudFindings))
	}
	if loaded.CloudFindings[0].RoleARN != "arn:aws:iam::123:role/admin" {
		t.Errorf("expected arn:aws:iam::123:role/admin, got %s", loaded.CloudFindings[0].RoleARN)
	}
}

func TestParseScanFindings_LegacyFormat(t *testing.T) {
	// Legacy format: flat JSON without version/findings wrapper
	legacy := map[string]interface{}{
		"timestamp": "2025-01-01T00:00:00Z",
		"rbac_findings": []map[string]interface{}{
			{
				"check_id": "RBAC001",
				"title":    "Test finding",
				"severity": "high",
			},
		},
		"pod_security_findings":  []interface{}{},
		"network_policy_findings": []interface{}{},
		"cloud_findings":         []interface{}{},
	}

	data, err := json.Marshal(legacy)
	if err != nil {
		t.Fatal(err)
	}

	findings, err := ParseScanFindings(data)
	if err != nil {
		t.Fatalf("ParseScanFindings failed for legacy format: %v", err)
	}

	if len(findings.RBACFindings) != 1 {
		t.Errorf("expected 1 RBAC finding from legacy format, got %d", len(findings.RBACFindings))
	}
}

func TestParseScanFindings_NewFormat(t *testing.T) {
	snap := &Snapshot{
		Version:   "1.0",
		Timestamp: "2025-01-01T00:00:00Z",
		GraphStats: &SnapshotGraphStats{
			TotalNodes: 10,
		},
		Findings: ScanFindings{
			RBACFindings: []RBACFinding{
				{CheckID: "RBAC002", Title: "New format finding", Severity: graph.SeverityMedium},
			},
		},
	}

	data, err := json.Marshal(snap)
	if err != nil {
		t.Fatal(err)
	}

	findings, err := ParseScanFindings(data)
	if err != nil {
		t.Fatalf("ParseScanFindings failed for new format: %v", err)
	}

	if len(findings.RBACFindings) != 1 {
		t.Errorf("expected 1 RBAC finding from new format, got %d", len(findings.RBACFindings))
	}
	if findings.RBACFindings[0].CheckID != "RBAC002" {
		t.Errorf("expected RBAC002, got %s", findings.RBACFindings[0].CheckID)
	}
}

func TestLoadScanFindings_NotFound(t *testing.T) {
	_, err := LoadScanFindings("/nonexistent/path/to/file.json")
	if err == nil {
		t.Error("expected error for nonexistent file")
	}
}

func TestWriteSnapshot_Stdout(t *testing.T) {
	snap := NewSnapshot(ScanFindings{}, nil)

	// Redirect stdout
	old := os.Stdout
	_, w, _ := os.Pipe()
	os.Stdout = w

	err := WriteSnapshot(snap, "")
	w.Close()
	os.Stdout = old

	if err != nil {
		t.Errorf("WriteSnapshot to stdout failed: %v", err)
	}
}

func TestSnapshotDiffRoundtrip(t *testing.T) {
	// Create baseline
	baseline := ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Finding A", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "ns1", Name: "r1"}}},
		},
	}

	// Create current with one new finding
	current := ScanFindings{
		RBACFindings: []RBACFinding{
			{CheckID: "RBAC001", Title: "Finding A", Severity: graph.SeverityHigh,
				Affected: []AffectedResource{{Namespace: "ns1", Name: "r1"}}},
			{CheckID: "RBAC002", Title: "Finding B", Severity: graph.SeverityCritical,
				Affected: []AffectedResource{{Namespace: "ns2", Name: "r2"}}},
		},
	}

	dir := t.TempDir()

	// Write both snapshots
	baseSnap := NewSnapshot(baseline, nil)
	curSnap := NewSnapshot(current, nil)

	basePath := filepath.Join(dir, "baseline.json")
	curPath := filepath.Join(dir, "current.json")

	if err := WriteSnapshot(baseSnap, basePath); err != nil {
		t.Fatal(err)
	}
	if err := WriteSnapshot(curSnap, curPath); err != nil {
		t.Fatal(err)
	}

	// Load and diff
	baseLoaded, err := LoadScanFindings(basePath)
	if err != nil {
		t.Fatal(err)
	}
	curLoaded, err := LoadScanFindings(curPath)
	if err != nil {
		t.Fatal(err)
	}

	result := ComputeDiff(baseLoaded, curLoaded)

	if result.Summary.NewCount != 1 {
		t.Errorf("expected 1 new finding, got %d", result.Summary.NewCount)
	}
	if result.Summary.Status != "degraded" {
		t.Errorf("expected degraded, got %s", result.Summary.Status)
	}
}
