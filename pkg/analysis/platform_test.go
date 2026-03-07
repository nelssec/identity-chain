package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// TestDetectPlatform_Empty verifies that DetectPlatform returns a valid result
// even when the graph is empty (no nodes at all).
func TestDetectPlatform_Empty(t *testing.T) {
	g := graph.New()

	result := DetectPlatform(g)

	if result == nil {
		t.Fatal("DetectPlatform returned nil for empty graph")
	}
	if result.Primary.Platform == "" {
		t.Errorf("expected a non-empty platform name, got empty string")
	}
	// Empty graph → vanilla
	if result.Primary.Platform != "vanilla" {
		t.Errorf("expected platform 'vanilla' for empty graph, got %q", result.Primary.Platform)
	}
	if result.Primary.FeatureFlags == nil {
		t.Errorf("expected non-nil FeatureFlags map")
	}
}

// TestDetectPlatform_OpenShift verifies that DetectPlatform returns "openshift"
// when the graph contains SCC nodes (added by the OpenShift collector).
func TestDetectPlatform_OpenShift(t *testing.T) {
	g := graph.New()

	// Add a mock SCC node – the same type the OpenShiftCollector adds.
	sccNode := &graph.Node{
		ID:   "scc:restricted",
		Type: graph.NodeSCC,
		Name: "restricted",
	}
	if err := g.AddNode(sccNode); err != nil {
		t.Fatalf("failed to add SCC node: %v", err)
	}

	result := DetectPlatform(g)

	if result.Primary.Platform != "openshift" {
		t.Errorf("expected platform 'openshift', got %q", result.Primary.Platform)
	}
	if !result.Primary.FeatureFlags["scc"] {
		t.Errorf("expected FeatureFlags[\"scc\"] = true for OpenShift")
	}
}

// TestDetectPlatform_EKS verifies that DetectPlatform returns "eks" when the
// graph contains an AWS cloud role and an SA with an IRSA annotation.
func TestDetectPlatform_EKS(t *testing.T) {
	g := graph.New()

	saNode := &graph.Node{
		ID:        graph.GenerateNodeID(graph.NodeServiceAccount, "default", "irsa-sa"),
		Type:      graph.NodeServiceAccount,
		Name:      "irsa-sa",
		Namespace: "default",
		Metadata: graph.NodeMetadata{
			CloudRoleARN: "arn:aws:iam::123456789012:role/my-irsa-role",
		},
	}
	if err := g.AddNode(saNode); err != nil {
		t.Fatalf("failed to add SA node: %v", err)
	}

	cloudRoleNode := &graph.Node{
		ID:   "cloudRole:my-irsa-role",
		Type: graph.NodeCloudRole,
		Name: "my-irsa-role",
		Metadata: graph.NodeMetadata{
			CloudProvider: "aws",
			CloudRoleARN:  "arn:aws:iam::123456789012:role/my-irsa-role",
		},
	}
	if err := g.AddNode(cloudRoleNode); err != nil {
		t.Fatalf("failed to add cloud role node: %v", err)
	}

	result := DetectPlatform(g)

	if result.Primary.Platform != "eks" {
		t.Errorf("expected platform 'eks', got %q", result.Primary.Platform)
	}
	if result.Primary.CloudProvider != "aws" {
		t.Errorf("expected cloud_provider 'aws', got %q", result.Primary.CloudProvider)
	}
	if !result.CloudIdentities.HasAWSIRSA {
		t.Errorf("expected HasAWSIRSA = true")
	}
	if len(result.CloudIdentities.AWSRoleARNs) == 0 {
		t.Errorf("expected at least one entry in AWSRoleARNs")
	}
}

// TestDetectPlatform_GKE verifies GKE detection via GCP service account annotations.
func TestDetectPlatform_GKE(t *testing.T) {
	g := graph.New()

	saNode := &graph.Node{
		ID:        graph.GenerateNodeID(graph.NodeServiceAccount, "default", "wi-sa"),
		Type:      graph.NodeServiceAccount,
		Name:      "wi-sa",
		Namespace: "default",
		Metadata: graph.NodeMetadata{
			GCPServiceAccount: "my-sa@my-project.iam.gserviceaccount.com",
		},
	}
	if err := g.AddNode(saNode); err != nil {
		t.Fatalf("failed to add SA node: %v", err)
	}

	cloudRoleNode := &graph.Node{
		ID:   "cloudRole:my-gcp-sa",
		Type: graph.NodeCloudRole,
		Name: "my-gcp-sa",
		Metadata: graph.NodeMetadata{
			CloudProvider: "gcp",
		},
	}
	if err := g.AddNode(cloudRoleNode); err != nil {
		t.Fatalf("failed to add cloud role node: %v", err)
	}

	result := DetectPlatform(g)

	if result.Primary.Platform != "gke" {
		t.Errorf("expected platform 'gke', got %q", result.Primary.Platform)
	}
	if result.Primary.CloudProvider != "gcp" {
		t.Errorf("expected cloud_provider 'gcp', got %q", result.Primary.CloudProvider)
	}
	if !result.CloudIdentities.HasGCPWorkloadID {
		t.Errorf("expected HasGCPWorkloadID = true")
	}
}

// TestDetectPlatform_WithDistroProfile verifies that a pre-set DistroProfile on
// the graph is honoured directly by DetectPlatform.
func TestDetectPlatform_WithDistroProfile(t *testing.T) {
	g := graph.New()
	g.DistroProfile = &graph.GraphDistroProfile{
		Platform:      "rke2",
		CloudProvider: "",
		FeatureFlags:  map[string]bool{"rke2": true},
	}

	result := DetectPlatform(g)

	if result.Primary.Platform != "rke2" {
		t.Errorf("expected platform 'rke2' from DistroProfile, got %q", result.Primary.Platform)
	}
	if !result.Primary.FeatureFlags["rke2"] {
		t.Errorf("expected FeatureFlags[\"rke2\"] = true")
	}
}

// ---------------------------------------------------------------------------
// RunPlatformChecks tests
// ---------------------------------------------------------------------------

// TestRunPlatformChecks_Empty verifies that RunPlatformChecks returns a valid
// result (not nil) when called with an empty graph and a nil platform result.
func TestRunPlatformChecks_Empty(t *testing.T) {
	g := graph.New()

	result := RunPlatformChecks(g, nil)

	if result == nil {
		t.Fatal("RunPlatformChecks returned nil")
	}
	if result.TotalChecks != 0 {
		t.Errorf("expected 0 total checks for nil platform, got %d", result.TotalChecks)
	}
}

// TestRunPlatformChecks_Vanilla verifies common checks run on a vanilla cluster.
func TestRunPlatformChecks_Vanilla(t *testing.T) {
	g := graph.New()

	platform := &PlatformDetectionResult{
		Primary: DistroProfile{
			Platform:     "vanilla",
			FeatureFlags: map[string]bool{},
		},
	}

	result := RunPlatformChecks(g, platform)

	if result == nil {
		t.Fatal("RunPlatformChecks returned nil")
	}
	if result.Platform != "vanilla" {
		t.Errorf("expected platform 'vanilla', got %q", result.Platform)
	}
	// The common check (CMN001) should always run.
	if result.TotalChecks == 0 {
		t.Errorf("expected at least 1 check (CMN001), got 0")
	}
}

// TestRunPlatformChecks_EKSIRSACheck verifies that EKS-specific checks run
// when platform is "eks".
func TestRunPlatformChecks_EKSIRSACheck(t *testing.T) {
	g := graph.New()

	// SA with IRSA annotation and a non-standard token audience
	saNode := &graph.Node{
		ID:        graph.GenerateNodeID(graph.NodeServiceAccount, "default", "irsa-sa"),
		Type:      graph.NodeServiceAccount,
		Name:      "irsa-sa",
		Namespace: "default",
		Metadata: graph.NodeMetadata{
			CloudRoleARN:  "arn:aws:iam::123456789012:role/my-role",
			TokenAudience: "custom-audience", // not sts.amazonaws.com
		},
	}
	if err := g.AddNode(saNode); err != nil {
		t.Fatalf("failed to add SA node: %v", err)
	}

	platform := &PlatformDetectionResult{
		Primary: DistroProfile{
			Platform:     "eks",
			CloudProvider: "aws",
			FeatureFlags: map[string]bool{"irsa": true},
		},
		CloudIdentities: CloudIdentities{
			HasAWSIRSA: true,
		},
	}

	result := RunPlatformChecks(g, platform)

	if result == nil {
		t.Fatal("RunPlatformChecks returned nil")
	}
	if result.Platform != "eks" {
		t.Errorf("expected platform 'eks', got %q", result.Platform)
	}
	// EKS001 should be present and failed (custom audience).
	foundEKS001 := false
	for _, f := range result.Findings {
		if f.CheckID == "EKS001" {
			foundEKS001 = true
			if f.Passed {
				t.Errorf("EKS001 should fail when IRSA SA has non-standard token audience")
			}
		}
	}
	if !foundEKS001 {
		t.Errorf("expected EKS001 check in platform findings")
	}
}
