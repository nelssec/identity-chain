package collector

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/collector/distro"
)

func TestShouldIncludeNamespace_SingleNamespace(t *testing.T) {
	opts := Options{
		Namespace:     "production",
		AllNamespaces: false,
	}

	cases := []struct {
		ns   string
		want bool
	}{
		{"production", true},
		{"staging", false},
		{"kube-system", false},
		{"default", false},
	}

	for _, tc := range cases {
		got := opts.ShouldIncludeNamespace(tc.ns)
		if got != tc.want {
			t.Errorf("ShouldIncludeNamespace(%q) with Namespace=%q: got %v, want %v",
				tc.ns, opts.Namespace, got, tc.want)
		}
	}
}

func TestShouldIncludeNamespace_AllNamespacesIncludeSystem(t *testing.T) {
	opts := Options{
		AllNamespaces: true,
		IncludeSystem: true,
	}

	cases := []struct {
		ns   string
		want bool
	}{
		{"production", true},
		{"kube-system", true},
		{"kube-public", true},
		{"kube-node-lease", true},
		{"openshift-monitoring", true},
		{"default", true},
	}

	for _, tc := range cases {
		got := opts.ShouldIncludeNamespace(tc.ns)
		if got != tc.want {
			t.Errorf("ShouldIncludeNamespace(%q) AllNamespaces+IncludeSystem: got %v, want %v",
				tc.ns, got, tc.want)
		}
	}
}

func TestShouldIncludeNamespace_AllNamespacesExcludeSystem(t *testing.T) {
	opts := Options{
		AllNamespaces: true,
		IncludeSystem: false,
	}

	cases := []struct {
		ns   string
		want bool
	}{
		{"production", true},
		{"default", true},
		{"my-app", true},
		// System namespaces should be excluded
		{"kube-system", false},
		{"kube-public", false},
		{"kube-node-lease", false},
		{"openshift-monitoring", false},
		{"cattle-system", false},
		{"fleet-default", false},
		{"rancher-monitoring", false},
	}

	for _, tc := range cases {
		got := opts.ShouldIncludeNamespace(tc.ns)
		if got != tc.want {
			t.Errorf("ShouldIncludeNamespace(%q) AllNamespaces-ExcludeSystem: got %v, want %v",
				tc.ns, got, tc.want)
		}
	}
}

func TestIsSystemNamespace_StandardNamespaces(t *testing.T) {
	cases := []struct {
		ns   string
		want bool
	}{
		{"kube-system", true},
		{"kube-public", true},
		{"kube-node-lease", true},
		{"default", false},
		{"production", false},
		{"my-namespace", false},
		{"", false},
	}

	for _, tc := range cases {
		got := IsSystemNamespace(tc.ns)
		if got != tc.want {
			t.Errorf("IsSystemNamespace(%q): got %v, want %v", tc.ns, got, tc.want)
		}
	}
}

func TestIsSystemNamespace_DistroPrefixes(t *testing.T) {
	cases := []struct {
		ns   string
		want bool
	}{
		// OpenShift prefixes
		{"openshift-monitoring", true},
		{"openshift-ingress", true},
		{"openshift-console", true},
		// Rancher / RKE2 prefixes
		{"cattle-system", true},
		{"cattle-fleet-system", true},
		{"fleet-default", true},
		{"fleet-local", true},
		{"rancher-monitoring", true},
		{"rancher-operator-system", true},
		// Non-system
		{"openshift", false}, // exact match, not prefix
		{"cattle", false},
		{"fleet", false},
		{"rancher", false},
		{"my-openshift-app", false},
	}

	for _, tc := range cases {
		got := IsSystemNamespace(tc.ns)
		if got != tc.want {
			t.Errorf("IsSystemNamespace(%q): got %v, want %v", tc.ns, got, tc.want)
		}
	}
}

func TestIsSystemNamespace_WithDistroProfile(t *testing.T) {
	profile := distro.DistroProfile{
		Platform:                "custom",
		SystemNamespacePrefixes: []string{"custom-system-", "internal-"},
	}

	cases := []struct {
		ns   string
		want bool
	}{
		// Standard system namespaces still match
		{"kube-system", true},
		// Profile-specific prefixes
		{"custom-system-foo", true},
		{"internal-bar", true},
		// Non-system
		{"production", false},
		{"custom-app", false},
	}

	for _, tc := range cases {
		got := IsSystemNamespace(tc.ns, profile)
		if got != tc.want {
			t.Errorf("IsSystemNamespace(%q, profile): got %v, want %v", tc.ns, got, tc.want)
		}
	}
}

func TestIsSystemNamespace_EmptyAndEdgeCases(t *testing.T) {
	cases := []struct {
		ns   string
		want bool
	}{
		{"", false},
		{"k", false},
		{"kube", false},
		{"kube-", false},
		{"KUBE-SYSTEM", false}, // case-sensitive
		{"Kube-System", false},
	}

	for _, tc := range cases {
		got := IsSystemNamespace(tc.ns)
		if got != tc.want {
			t.Errorf("IsSystemNamespace(%q): got %v, want %v", tc.ns, got, tc.want)
		}
	}
}
