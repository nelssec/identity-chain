package collector

import (
	"context"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type Collector interface {
	Collect(ctx context.Context, builder *graph.Builder) error
}

type Options struct {
	Namespace      string
	AllNamespaces  bool
	IncludeSystem  bool
	KubeConfigPath string
	KubeContext    string
}

func (o Options) ShouldIncludeNamespace(ns string) bool {
	if o.AllNamespaces {
		if !o.IncludeSystem && IsSystemNamespace(ns) {
			return false
		}
		return true
	}
	return ns == o.Namespace
}

// IsSystemNamespace returns true if the namespace is a Kubernetes system namespace.
// It covers the standard set plus common distro-specific namespaces (openshift-*,
// cattle-*, fleet-*, rancher-*). An optional DistroProfile can be passed to
// include platform-specific prefixes; pass nil to use the defaults only.
func IsSystemNamespace(ns string, profiles ...interface{ IsSystemNamespace(string) bool }) bool {
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}
	if systemNamespaces[ns] {
		return true
	}
	// Default distro-specific prefixes (always applied for convenience).
	defaultPrefixes := []string{"openshift-", "cattle-", "fleet-", "rancher-"}
	for _, p := range defaultPrefixes {
		if len(ns) >= len(p) && ns[:len(p)] == p {
			return true
		}
	}
	// If a DistroProfile is provided, delegate to it for additional patterns.
	for _, prof := range profiles {
		if prof.IsSystemNamespace(ns) {
			return true
		}
	}
	return false
}
