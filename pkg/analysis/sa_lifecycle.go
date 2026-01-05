package analysis

import (
	"sort"
	"time"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type SALifecycleResult struct {
	OrphanedSAs []OrphanedSA
	StaleSAs    []StaleSA
	UnboundSAs  []UnboundSA
	Summary     SALifecycleSummary
}

type SALifecycleSummary struct {
	TotalSAs      int
	OrphanedCount int
	StaleCount    int
	UnboundCount  int
	HealthyCount  int
}

type OrphanedSA struct {
	Name           string
	Namespace      string
	HasBindings    bool
	BindingCount   int
	UsedByWorkload bool
	Reason         string
}

type StaleSA struct {
	Name         string
	Namespace    string
	LastActivity time.Time
	DaysSinceUse int
	HasBindings  bool
}

type UnboundSA struct {
	Name      string
	Namespace string
	UsedBy    []string
}

type SALifecycleOptions struct {
	StaleThresholdDays int
	IncludeSystem      bool
}

func AnalyzeSALifecycle(g *graph.Graph, opts SALifecycleOptions) *SALifecycleResult {
	if opts.StaleThresholdDays == 0 {
		opts.StaleThresholdDays = 30
	}

	result := &SALifecycleResult{}

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)

	saUsage := make(map[string][]string)
	for _, sa := range serviceAccounts {
		inEdges := g.GetInEdges(sa.ID)
		for _, edge := range inEdges {
			if edge.Type == graph.EdgeUses {
				workload := g.GetNode(edge.From)
				if workload != nil {
					saUsage[sa.ID] = append(saUsage[sa.ID], workload.Name)
				}
			}
		}
	}

	saBindings := make(map[string]int)
	for _, sa := range serviceAccounts {
		edges := g.GetOutEdges(sa.ID)
		bindingCount := 0
		for _, edge := range edges {
			if edge.Type == graph.EdgeBinds {
				bindingCount++
			}
		}
		saBindings[sa.ID] = bindingCount
	}

	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && isSystemSA(sa.Namespace, sa.Name) {
			continue
		}

		usedBy := saUsage[sa.ID]
		bindingCount := saBindings[sa.ID]

		if len(usedBy) == 0 && bindingCount > 0 {
			reason := "Has RBAC bindings but not used by any workload"
			result.OrphanedSAs = append(result.OrphanedSAs, OrphanedSA{
				Name:           sa.Name,
				Namespace:      sa.Namespace,
				HasBindings:    true,
				BindingCount:   bindingCount,
				UsedByWorkload: false,
				Reason:         reason,
			})
		}

		if bindingCount == 0 && len(usedBy) > 0 {
			result.UnboundSAs = append(result.UnboundSAs, UnboundSA{
				Name:      sa.Name,
				Namespace: sa.Namespace,
				UsedBy:    usedBy,
			})
		}

		if len(usedBy) == 0 && bindingCount == 0 {
			reason := "No bindings and not used by any workload"
			result.OrphanedSAs = append(result.OrphanedSAs, OrphanedSA{
				Name:           sa.Name,
				Namespace:      sa.Namespace,
				HasBindings:    false,
				BindingCount:   0,
				UsedByWorkload: false,
				Reason:         reason,
			})
		}
	}

	sort.Slice(result.OrphanedSAs, func(i, j int) bool {
		if result.OrphanedSAs[i].Namespace != result.OrphanedSAs[j].Namespace {
			return result.OrphanedSAs[i].Namespace < result.OrphanedSAs[j].Namespace
		}
		return result.OrphanedSAs[i].Name < result.OrphanedSAs[j].Name
	})

	totalFiltered := 0
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && isSystemSA(sa.Namespace, sa.Name) {
			continue
		}
		totalFiltered++
	}

	result.Summary = SALifecycleSummary{
		TotalSAs:      totalFiltered,
		OrphanedCount: len(result.OrphanedSAs),
		StaleCount:    len(result.StaleSAs),
		UnboundCount:  len(result.UnboundSAs),
		HealthyCount:  totalFiltered - len(result.OrphanedSAs) - len(result.UnboundSAs),
	}

	return result
}

func isSystemSA(namespace, name string) bool {
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}

	if systemNamespaces[namespace] {
		return true
	}

	if name == "default" {
		return true
	}

	return false
}

func (a *SALifecycleResult) GetCleanupYAML() string {
	var yaml string

	for _, sa := range a.OrphanedSAs {
		yaml += "---\n"
		yaml += "# Orphaned: " + sa.Reason + "\n"
		yaml += "apiVersion: v1\n"
		yaml += "kind: ServiceAccount\n"
		yaml += "metadata:\n"
		yaml += "  name: " + sa.Name + "\n"
		yaml += "  namespace: " + sa.Namespace + "\n"
		yaml += "  annotations:\n"
		yaml += "    idc.io/action: delete\n"
		yaml += "    idc.io/reason: orphaned\n"
	}

	return yaml
}
