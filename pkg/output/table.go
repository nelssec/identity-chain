package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type TableWriter struct {
	w io.Writer
}

func NewTableWriter(w io.Writer) *TableWriter {
	return &TableWriter{w: w}
}

func (t *TableWriter) WriteBlastResult(result *analysis.BlastResult) error {
	if result == nil {
		fmt.Fprintln(t.w, "No results found")
		return nil
	}

	fmt.Fprintf(t.w, "\n=== Blast Radius Analysis ===\n\n")

	if result.SourceWorkload != nil {
		fmt.Fprintf(t.w, "Workload:        %s/%s (%s)\n",
			result.SourceWorkload.Namespace,
			result.SourceWorkload.Name,
			result.SourceWorkload.Metadata.WorkloadKind)
	}

	if result.ServiceAccount != nil {
		fmt.Fprintf(t.w, "ServiceAccount:  %s/%s\n",
			result.ServiceAccount.Namespace,
			result.ServiceAccount.Name)

		if result.ServiceAccount.HasCloudIdentity() {
			if result.ServiceAccount.Metadata.CloudRoleARN != "" {
				fmt.Fprintf(t.w, "AWS Role:        %s\n", result.ServiceAccount.Metadata.CloudRoleARN)
			}
			if result.ServiceAccount.Metadata.GCPServiceAccount != "" {
				fmt.Fprintf(t.w, "GCP SA:          %s\n", result.ServiceAccount.Metadata.GCPServiceAccount)
			}
			if result.ServiceAccount.Metadata.AzureManagedID != "" {
				fmt.Fprintf(t.w, "Azure MI:        %s\n", result.ServiceAccount.Metadata.AzureManagedID)
			}
		}
	}

	fmt.Fprintf(t.w, "Max Severity:    %s\n", severityColor(result.MaxSeverity))
	fmt.Fprintf(t.w, "K8s Permissions: %d\n", result.TotalK8sPerms)
	fmt.Fprintf(t.w, "Cloud Roles:     %d\n", result.TotalCloudPerms)

	if len(result.K8sResources) > 0 {
		fmt.Fprintf(t.w, "\n--- Kubernetes Resource Access ---\n\n")
		fmt.Fprintf(t.w, "%-30s %-30s %-20s %-10s\n", "RESOURCE", "VERBS", "VIA ROLE", "SEVERITY")
		fmt.Fprintf(t.w, "%-30s %-30s %-20s %-10s\n", "--------", "-----", "--------", "--------")

		for _, access := range result.K8sResources {
			resourceName := access.Resource.Name
			if access.Resource.Namespace != "" {
				resourceName = access.Resource.Namespace + "/" + resourceName
			}
			if len(resourceName) > 28 {
				resourceName = resourceName[:28] + ".."
			}
			verbs := strings.Join(access.Verbs, ", ")
			if len(verbs) > 28 {
				verbs = verbs[:28] + ".."
			}
			fmt.Fprintf(t.w, "%-30s %-30s %-20s %-10s\n",
				resourceName,
				verbs,
				access.ViaRole,
				string(access.Severity))
		}
	}

	if len(result.CloudRoles) > 0 {
		fmt.Fprintf(t.w, "\n--- Cloud Role Access ---\n\n")
		fmt.Fprintf(t.w, "%-10s %-60s %-10s\n", "PROVIDER", "ROLE ARN", "SEVERITY")
		fmt.Fprintf(t.w, "%-10s %-60s %-10s\n", "--------", "--------", "--------")

		for _, access := range result.CloudRoles {
			roleARN := access.RoleARN
			if len(roleARN) > 58 {
				roleARN = roleARN[:58] + ".."
			}
			fmt.Fprintf(t.w, "%-10s %-60s %-10s\n",
				access.Provider,
				roleARN,
				string(access.Severity))
		}
	}

	fmt.Fprintln(t.w)
	return nil
}

func (t *TableWriter) WriteBlastResults(results []*analysis.BlastResult) error {
	if len(results) == 0 {
		fmt.Fprintln(t.w, "No workloads found")
		return nil
	}

	fmt.Fprintf(t.w, "\n=== Workload Blast Radius Summary ===\n\n")

	fmt.Fprintf(t.w, "%-25s %-15s %-20s %-12s %-12s %-10s\n",
		"WORKLOAD", "NAMESPACE", "SERVICE ACCOUNT", "K8S PERMS", "CLOUD ROLES", "SEVERITY")
	fmt.Fprintf(t.w, "%-25s %-15s %-20s %-12s %-12s %-10s\n",
		"--------", "---------", "---------------", "---------", "-----------", "--------")

	for _, result := range results {
		workloadName := ""
		namespace := ""
		saName := ""

		if result.SourceWorkload != nil {
			workloadName = result.SourceWorkload.Name
			if len(workloadName) > 23 {
				workloadName = workloadName[:23] + ".."
			}
			namespace = result.SourceWorkload.Namespace
			if len(namespace) > 13 {
				namespace = namespace[:13] + ".."
			}
		}
		if result.ServiceAccount != nil {
			saName = result.ServiceAccount.Name
			if len(saName) > 18 {
				saName = saName[:18] + ".."
			}
		}

		fmt.Fprintf(t.w, "%-25s %-15s %-20s %-12d %-12d %-10s\n",
			workloadName,
			namespace,
			saName,
			result.TotalK8sPerms,
			result.TotalCloudPerms,
			string(result.MaxSeverity))
	}

	criticalCount := 0
	highCount := 0
	for _, r := range results {
		switch r.MaxSeverity {
		case graph.SeverityCritical:
			criticalCount++
		case graph.SeverityHigh:
			highCount++
		}
	}

	fmt.Fprintf(t.w, "\nTotal: %d workloads | Critical: %d | High: %d\n\n", len(results), criticalCount, highCount)

	return nil
}

func (t *TableWriter) WriteGraph(g *graph.Graph) error {
	stats := g.Stats()
	return t.WriteStats(stats)
}

func (t *TableWriter) WriteStats(stats graph.GraphStats) error {
	fmt.Fprintf(t.w, "\n=== Graph Statistics ===\n\n")
	fmt.Fprintf(t.w, "Total Nodes: %d\n", stats.TotalNodes)
	fmt.Fprintf(t.w, "Total Edges: %d\n\n", stats.TotalEdges)

	fmt.Fprintln(t.w, "Node Counts:")
	for nodeType, count := range stats.NodeCounts {
		fmt.Fprintf(t.w, "  %-20s %d\n", nodeType, count)
	}

	fmt.Fprintln(t.w, "\nEdge Counts:")
	for edgeType, count := range stats.EdgeCounts {
		fmt.Fprintf(t.w, "  %-20s %d\n", edgeType, count)
	}

	fmt.Fprintln(t.w)
	return nil
}

func severityColor(s graph.Severity) string {
	switch s {
	case graph.SeverityCritical:
		return "\033[31m" + string(s) + "\033[0m"
	case graph.SeverityHigh:
		return "\033[33m" + string(s) + "\033[0m"
	case graph.SeverityMedium:
		return "\033[36m" + string(s) + "\033[0m"
	default:
		return string(s)
	}
}
