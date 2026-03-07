package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestDetectPlatform_Empty(t *testing.T) {
	g := graph.New()
	result := DetectPlatform(g)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Primary.Platform != "kubernetes" {
		t.Errorf("expected platform 'kubernetes', got %q", result.Primary.Platform)
	}
	if result.Primary.CloudProvider != "unknown" {
		t.Errorf("expected cloud provider 'unknown', got %q", result.Primary.CloudProvider)
	}
}

func TestRunPlatformChecks_Empty(t *testing.T) {
	g := graph.New()
	platform := DetectPlatform(g)
	result := RunPlatformChecks(g, platform)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.Platform != "kubernetes" {
		t.Errorf("expected platform 'kubernetes', got %q", result.Platform)
	}
	// Generic checks should produce at least 1 finding.
	if len(result.Findings) == 0 {
		t.Error("expected at least one finding from generic checks")
	}
}

func TestAnalyzeExploitablePermissions_Empty(t *testing.T) {
	g := graph.New()
	platform := DetectPlatform(g)
	result := AnalyzeExploitablePermissions(g, platform)
	if result == nil {
		t.Fatal("expected non-nil result")
	}
	if result.CriticalCount != 0 || result.HighCount != 0 || result.MediumCount != 0 || result.LowCount != 0 {
		t.Error("expected zero counts on empty graph")
	}
}

func TestExploitablePermResult_HasSubjectAndCategory(t *testing.T) {
	f := ExploitablePermFinding{
		Identity: "test-sa",
		Subject: ExploitablePermSubject{
			Namespace: "default",
			Name:      "test-sa",
			Kind:      "ServiceAccount",
		},
		Category: "over_permissive",
		Title:    "Test finding",
		Severity: graph.SeverityCritical,
	}
	if f.Subject.Name != "test-sa" {
		t.Errorf("expected subject name 'test-sa', got %q", f.Subject.Name)
	}
	if f.Category != "over_permissive" {
		t.Errorf("expected category 'over_permissive', got %q", f.Category)
	}
}
