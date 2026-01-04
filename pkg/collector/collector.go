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
		if !o.IncludeSystem && isSystemNamespace(ns) {
			return false
		}
		return true
	}
	return ns == o.Namespace
}

func isSystemNamespace(ns string) bool {
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}
	return systemNamespaces[ns]
}
