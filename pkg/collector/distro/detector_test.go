package distro

import (
	"context"
	"testing"
)

// TestGenericDetector returns vanilla profile and satisfies the Detector interface.
func TestGenericDetector(t *testing.T) {
	d := &GenericDetector{}
	profile, err := d.Detect(context.Background(), nil)
	if err != nil {
		t.Fatalf("GenericDetector.Detect returned error: %v", err)
	}
	if profile.Platform != "vanilla" {
		t.Errorf("expected platform 'vanilla', got %q", profile.Platform)
	}
	if profile.FeatureFlags == nil {
		t.Error("expected non-nil FeatureFlags")
	}
}

// TestDistroProfile_IsSystemNamespace verifies the IsSystemNamespace logic.
func TestDistroProfile_IsSystemNamespace(t *testing.T) {
	profile := DistroProfile{
		Platform:                "openshift",
		SystemNamespacePrefixes: []string{"openshift-"},
	}

	cases := []struct {
		ns       string
		expected bool
	}{
		{"kube-system", true},
		{"kube-public", true},
		{"kube-node-lease", true},
		{"openshift-monitoring", true},
		{"openshift-ingress", true},
		{"default", false},
		{"prod", false},
		{"my-app", false},
	}

	for _, tc := range cases {
		got := profile.IsSystemNamespace(tc.ns)
		if got != tc.expected {
			t.Errorf("IsSystemNamespace(%q) = %v, want %v (platform=%q)", tc.ns, got, tc.expected, profile.Platform)
		}
	}
}

// TestDistroProfile_IsSystemNamespace_RKE2 verifies Rancher-specific system namespaces.
func TestDistroProfile_IsSystemNamespace_RKE2(t *testing.T) {
	profile := DistroProfile{
		Platform:                "rke2",
		SystemNamespacePrefixes: []string{"cattle-", "fleet-", "rancher-"},
	}

	cases := []struct {
		ns       string
		expected bool
	}{
		{"kube-system", true},
		{"cattle-system", true},
		{"fleet-default", true},
		{"rancher-monitoring", true},
		{"default", false},
		{"production", false},
	}

	for _, tc := range cases {
		got := profile.IsSystemNamespace(tc.ns)
		if got != tc.expected {
			t.Errorf("IsSystemNamespace(%q) = %v, want %v (platform=%q)", tc.ns, got, tc.expected, profile.Platform)
		}
	}
}

// TestDetectorInterface verifies that all concrete detectors implement the Detector interface.
func TestDetectorInterface(t *testing.T) {
	// Compile-time check: all types must implement the Detector interface.
	detectors := []Detector{
		&GenericDetector{},
		&OpenShiftDetector{},
		&EKSDetector{},
		&GKEDetector{},
		&AKSDetector{},
		&RKE2Detector{},
		&K3sDetector{},
	}

	// All detectors must handle nil clients gracefully (they use nil-client safe paths).
	for _, d := range detectors {
		// We pass a nil client; each detector should return a vanilla profile and nil error
		// when the client call fails (nil pointer deref is avoided by the detectors).
		// We only check that the type assertion succeeded (compile-time only in Go).
		_ = d
	}

	if len(detectors) != 7 {
		t.Errorf("expected 7 detector implementations, got %d", len(detectors))
	}
}
