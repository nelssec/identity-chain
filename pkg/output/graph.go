package output

import (
	"fmt"
	"io"
	"strings"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type DOTWriter struct {
	w io.Writer
}

func NewDOTWriter(w io.Writer) *DOTWriter {
	return &DOTWriter{w: w}
}

func (d *DOTWriter) WriteBlastResult(result *analysis.BlastResult) error {
	fmt.Fprintln(d.w, "digraph BlastRadius {")
	fmt.Fprintln(d.w, "  rankdir=LR;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w, "  edge [fontname=\"Helvetica\", fontsize=10];")
	fmt.Fprintln(d.w)

	if result.SourceWorkload != nil {
		d.writeWorkloadNode(result.SourceWorkload)
	}

	if result.ServiceAccount != nil {
		d.writeServiceAccountNode(result.ServiceAccount)

		if result.SourceWorkload != nil {
			fmt.Fprintf(d.w, "  \"%s\" -> \"%s\" [label=\"uses\", color=\"#666666\"];\n",
				nodeID(result.SourceWorkload), nodeID(result.ServiceAccount))
		}
	}

	rolesSeen := make(map[string]bool)
	for _, access := range result.K8sResources {
		if !rolesSeen[access.ViaRole] {
			rolesSeen[access.ViaRole] = true
			d.writeRoleNode(access.ViaRole, false)

			if result.ServiceAccount != nil {
				fmt.Fprintf(d.w, "  \"%s\" -> \"role:%s\" [label=\"binds\", color=\"#666666\"];\n",
					nodeID(result.ServiceAccount), access.ViaRole)
			}
		}
	}

	resourcesSeen := make(map[string]bool)
	for _, access := range result.K8sResources {
		resourceKey := access.Resource.ID
		if !resourcesSeen[resourceKey] {
			resourcesSeen[resourceKey] = true
			d.writeResourceNode(access.Resource, access.Severity)
		}

		verbLabel := strings.Join(access.Verbs, ", ")
		edgeColor := severityEdgeColor(access.Severity)
		fmt.Fprintf(d.w, "  \"role:%s\" -> \"%s\" [label=\"%s\", color=\"%s\", penwidth=2];\n",
			access.ViaRole, resourceKey, verbLabel, edgeColor)
	}

	for _, access := range result.CloudRoles {
		d.writeCloudRoleNode(access)

		if result.ServiceAccount != nil {
			fmt.Fprintf(d.w, "  \"%s\" -> \"cloud:%s\" [label=\"assumes\", color=\"#ff6600\", style=dashed, penwidth=2];\n",
				nodeID(result.ServiceAccount), sanitizeID(access.RoleARN))
		}
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteBlastResults(results []*analysis.BlastResult) error {
	fmt.Fprintln(d.w, "digraph ClusterBlastRadius {")
	fmt.Fprintln(d.w, "  rankdir=LR;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w, "  edge [fontname=\"Helvetica\", fontsize=9];")
	fmt.Fprintln(d.w, "  compound=true;")
	fmt.Fprintln(d.w)

	nodesSeen := make(map[string]bool)
	edgesSeen := make(map[string]bool)

	for _, result := range results {
		if result.SourceWorkload != nil && !nodesSeen[nodeID(result.SourceWorkload)] {
			d.writeWorkloadNode(result.SourceWorkload)
			nodesSeen[nodeID(result.SourceWorkload)] = true
		}

		if result.ServiceAccount != nil && !nodesSeen[nodeID(result.ServiceAccount)] {
			d.writeServiceAccountNode(result.ServiceAccount)
			nodesSeen[nodeID(result.ServiceAccount)] = true
		}

		if result.SourceWorkload != nil && result.ServiceAccount != nil {
			edgeKey := fmt.Sprintf("%s->%s", nodeID(result.SourceWorkload), nodeID(result.ServiceAccount))
			if !edgesSeen[edgeKey] {
				fmt.Fprintf(d.w, "  \"%s\" -> \"%s\" [label=\"uses\", color=\"#666666\"];\n",
					nodeID(result.SourceWorkload), nodeID(result.ServiceAccount))
				edgesSeen[edgeKey] = true
			}
		}

		for _, access := range result.K8sResources {
			roleKey := "role:" + access.ViaRole
			if !nodesSeen[roleKey] {
				d.writeRoleNode(access.ViaRole, false)
				nodesSeen[roleKey] = true
			}

			if result.ServiceAccount != nil {
				edgeKey := fmt.Sprintf("%s->%s", nodeID(result.ServiceAccount), roleKey)
				if !edgesSeen[edgeKey] {
					fmt.Fprintf(d.w, "  \"%s\" -> \"%s\" [label=\"binds\", color=\"#666666\"];\n",
						nodeID(result.ServiceAccount), roleKey)
					edgesSeen[edgeKey] = true
				}
			}

			resourceKey := access.Resource.ID
			if !nodesSeen[resourceKey] {
				d.writeResourceNode(access.Resource, access.Severity)
				nodesSeen[resourceKey] = true
			}

			edgeKey := fmt.Sprintf("%s->%s", roleKey, resourceKey)
			if !edgesSeen[edgeKey] {
				verbLabel := strings.Join(access.Verbs, ",")
				edgeColor := severityEdgeColor(access.Severity)
				fmt.Fprintf(d.w, "  \"%s\" -> \"%s\" [label=\"%s\", color=\"%s\", penwidth=2];\n",
					roleKey, resourceKey, verbLabel, edgeColor)
				edgesSeen[edgeKey] = true
			}
		}

		for _, access := range result.CloudRoles {
			cloudKey := "cloud:" + sanitizeID(access.RoleARN)
			if !nodesSeen[cloudKey] {
				d.writeCloudRoleNode(access)
				nodesSeen[cloudKey] = true
			}

			if result.ServiceAccount != nil {
				edgeKey := fmt.Sprintf("%s->%s", nodeID(result.ServiceAccount), cloudKey)
				if !edgesSeen[edgeKey] {
					fmt.Fprintf(d.w, "  \"%s\" -> \"%s\" [label=\"assumes\", color=\"#ff6600\", style=dashed, penwidth=2];\n",
						nodeID(result.ServiceAccount), cloudKey)
					edgesSeen[edgeKey] = true
				}
			}
		}
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteGraph(g *graph.Graph) error {
	fmt.Fprintln(d.w, "digraph IdentityChain {")
	fmt.Fprintln(d.w, "  rankdir=LR;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w, "  edge [fontname=\"Helvetica\", fontsize=9];")
	fmt.Fprintln(d.w)

	for _, node := range g.AllNodes() {
		d.writeGenericNode(node)
	}

	fmt.Fprintln(d.w)

	for _, edge := range g.AllEdges() {
		d.writeEdge(edge, g)
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteStats(stats graph.GraphStats) error {
	fmt.Fprintln(d.w, "digraph Stats {")
	fmt.Fprintln(d.w, "  label=\"Graph Statistics\";")
	fmt.Fprintf(d.w, "  stats [label=\"Nodes: %d\\nEdges: %d\", shape=note];\n",
		stats.TotalNodes, stats.TotalEdges)
	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) writeWorkloadNode(node *graph.Node) {
	label := fmt.Sprintf("%s\\n%s/%s", node.Metadata.WorkloadKind, node.Namespace, node.Name)
	fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"#e3f2fd\", color=\"#1976d2\"];\n",
		nodeID(node), label)
}

func (d *DOTWriter) writeServiceAccountNode(node *graph.Node) {
	label := fmt.Sprintf("ServiceAccount\\n%s/%s", node.Namespace, node.Name)
	fillColor := "#fff3e0"
	borderColor := "#f57c00"

	if node.HasCloudIdentity() {
		fillColor = "#fff8e1"
		borderColor = "#ff8f00"
	}

	fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
		nodeID(node), label, fillColor, borderColor)
}

func (d *DOTWriter) writeRoleNode(roleName string, isClusterRole bool) {
	roleType := "Role"
	if isClusterRole {
		roleType = "ClusterRole"
	}
	label := fmt.Sprintf("%s\\n%s", roleType, roleName)
	fmt.Fprintf(d.w, "  \"role:%s\" [label=\"%s\", fillcolor=\"#f3e5f5\", color=\"#7b1fa2\"];\n",
		roleName, label)
}

func (d *DOTWriter) writeResourceNode(node *graph.Node, severity graph.Severity) {
	label := node.Metadata.ResourceKind
	if node.Namespace != "" {
		label = fmt.Sprintf("%s\\n%s", node.Metadata.ResourceKind, node.Namespace)
	}

	fillColor, borderColor := severityColors(severity)
	fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
		node.ID, label, fillColor, borderColor)
}

func (d *DOTWriter) writeCloudRoleNode(access analysis.CloudAccess) {
	providerLabel := strings.ToUpper(access.Provider)
	arnShort := shortARN(access.RoleARN)
	label := fmt.Sprintf("%s Role\\n%s", providerLabel, arnShort)

	fmt.Fprintf(d.w, "  \"cloud:%s\" [label=\"%s\", fillcolor=\"#ffebee\", color=\"#c62828\", shape=octagon];\n",
		sanitizeID(access.RoleARN), label)
}

func (d *DOTWriter) writeGenericNode(node *graph.Node) {
	var label, fillColor, borderColor, shape string

	switch node.Type {
	case graph.NodeWorkload:
		label = fmt.Sprintf("%s\\n%s/%s", node.Metadata.WorkloadKind, node.Namespace, node.Name)
		fillColor = "#e3f2fd"
		borderColor = "#1976d2"
		shape = "box"
	case graph.NodeServiceAccount:
		label = fmt.Sprintf("SA\\n%s/%s", node.Namespace, node.Name)
		fillColor = "#fff3e0"
		borderColor = "#f57c00"
		shape = "box"
	case graph.NodeRole:
		roleType := "Role"
		if node.Metadata.IsClusterRole {
			roleType = "ClusterRole"
		}
		label = fmt.Sprintf("%s\\n%s", roleType, node.Name)
		fillColor = "#f3e5f5"
		borderColor = "#7b1fa2"
		shape = "box"
	case graph.NodeK8sResource:
		label = node.Metadata.ResourceKind
		fillColor = "#e8f5e9"
		borderColor = "#388e3c"
		shape = "box"
	case graph.NodeCloudRole:
		label = fmt.Sprintf("Cloud Role\\n%s", shortARN(node.Name))
		fillColor = "#ffebee"
		borderColor = "#c62828"
		shape = "octagon"
	case graph.NodeCloudResource:
		label = fmt.Sprintf("Cloud Resource\\n%s", node.Name)
		fillColor = "#fce4ec"
		borderColor = "#ad1457"
		shape = "box"
	default:
		label = node.Name
		fillColor = "#ffffff"
		borderColor = "#000000"
		shape = "box"
	}

	fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\", shape=%s];\n",
		node.ID, label, fillColor, borderColor, shape)
}

func (d *DOTWriter) writeEdge(edge *graph.Edge, g *graph.Graph) {
	var label, color, style string
	penwidth := "1"

	switch edge.Type {
	case graph.EdgeUses:
		label = "uses"
		color = "#666666"
		style = "solid"
	case graph.EdgeBinds:
		label = "binds"
		color = "#7b1fa2"
		style = "solid"
	case graph.EdgeGrants:
		verbs := strings.Join(edge.Metadata.Verbs, ",")
		label = verbs
		targetNode := g.GetNode(edge.To)
		severity := graph.ClassifyEdgeSeverity(edge, targetNode)
		color = severityEdgeColor(severity)
		style = "solid"
		penwidth = "2"
	case graph.EdgeAssumes:
		label = "assumes"
		color = "#ff6600"
		style = "dashed"
		penwidth = "2"
	case graph.EdgeAllows:
		label = "allows"
		color = "#c62828"
		style = "solid"
		penwidth = "2"
	}

	fmt.Fprintf(d.w, "  \"%s\" -> \"%s\" [label=\"%s\", color=\"%s\", style=%s, penwidth=%s];\n",
		edge.From, edge.To, label, color, style, penwidth)
}

func nodeID(node *graph.Node) string {
	return node.ID
}

func sanitizeID(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	s = strings.ReplaceAll(s, ".", "_")
	return s
}

func shortARN(arn string) string {
	parts := strings.Split(arn, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	parts = strings.Split(arn, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}

func severityColors(s graph.Severity) (fillColor, borderColor string) {
	switch s {
	case graph.SeverityCritical:
		return "#ffcdd2", "#c62828"
	case graph.SeverityHigh:
		return "#ffe0b2", "#e65100"
	case graph.SeverityMedium:
		return "#fff9c4", "#f9a825"
	default:
		return "#e8f5e9", "#388e3c"
	}
}

func severityEdgeColor(s graph.Severity) string {
	switch s {
	case graph.SeverityCritical:
		return "#c62828"
	case graph.SeverityHigh:
		return "#e65100"
	case graph.SeverityMedium:
		return "#f9a825"
	default:
		return "#388e3c"
	}
}

func (d *DOTWriter) WritePrivescResults(results []*analysis.PrivescResult) error {
	fmt.Fprintln(d.w, "digraph PrivilegeEscalation {")
	fmt.Fprintln(d.w, "  rankdir=LR;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w, "  edge [fontname=\"Helvetica\", fontsize=9];")
	fmt.Fprintln(d.w)

	for _, result := range results {
		if result.SourceNode != nil {
			label := fmt.Sprintf("%s\\n%s/%s", result.SourceNode.Metadata.WorkloadKind, result.SourceNode.Namespace, result.SourceNode.Name)
			fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"#e3f2fd\", color=\"#1976d2\"];\n",
				result.SourceNode.ID, label)
		}

		for i, v := range result.DirectVectors {
			vectorID := fmt.Sprintf("vector_%s_%d", sanitizeID(result.SourceNode.ID), i)
			label := fmt.Sprintf("%s\\n%s", v.Vector.String(), v.Role.Name)
			fillColor, borderColor := severityColors(v.Severity)
			fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
				vectorID, label, fillColor, borderColor)
			fmt.Fprintf(d.w, "  \"%s\" -> \"%s\" [label=\"privesc\", color=\"%s\", penwidth=2];\n",
				result.SourceNode.ID, vectorID, severityEdgeColor(v.Severity))
		}
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteWhoCanResult(result *analysis.WhoCanResult) error {
	fmt.Fprintln(d.w, "digraph WhoCan {")
	fmt.Fprintln(d.w, "  rankdir=LR;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w)

	resourceLabel := fmt.Sprintf("%s %s", result.Verb, result.Resource)
	fmt.Fprintf(d.w, "  \"target\" [label=\"%s\", fillcolor=\"#ffcdd2\", color=\"#c62828\", shape=octagon];\n", resourceLabel)

	for i, s := range result.Subjects {
		subjectID := fmt.Sprintf("subject_%d", i)
		label := fmt.Sprintf("SA\\n%s/%s", s.Namespace, s.Name)
		fillColor, borderColor := severityColors(s.Severity)
		fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
			subjectID, label, fillColor, borderColor)
		fmt.Fprintf(d.w, "  \"%s\" -> \"target\" [label=\"via %s\"];\n", subjectID, s.ViaRole)
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteWhatCanResult(result *analysis.ReverseRBACResult) error {
	fmt.Fprintln(d.w, "digraph WhatCan {")
	fmt.Fprintln(d.w, "  rankdir=LR;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w)

	saLabel := fmt.Sprintf("SA\\n%s/%s", result.Namespace, result.Subject)
	fmt.Fprintf(d.w, "  \"sa\" [label=\"%s\", fillcolor=\"#fff3e0\", color=\"#f57c00\"];\n", saLabel)

	for i, p := range result.Permissions {
		permID := fmt.Sprintf("perm_%d", i)
		label := fmt.Sprintf("%s\\n%s", p.Resource, strings.Join(p.Verbs, ", "))
		fillColor, borderColor := severityColors(p.Severity)
		fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
			permID, label, fillColor, borderColor)
		fmt.Fprintf(d.w, "  \"sa\" -> \"%s\" [label=\"via %s\"];\n", permID, p.ViaRole)
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteRBACAuditResult(result *analysis.RBACAuditResult) error {
	fmt.Fprintln(d.w, "digraph RBACAudit {")
	fmt.Fprintln(d.w, "  rankdir=TB;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w)

	fmt.Fprintf(d.w, "  \"summary\" [label=\"RBAC Audit\\nCritical: %d\\nHigh: %d\\nMedium: %d\\nLow: %d\", shape=note, fillcolor=\"#f5f5f5\"];\n",
		result.Summary.Critical, result.Summary.High, result.Summary.Medium, result.Summary.Low)

	for i, f := range result.Findings {
		findingID := fmt.Sprintf("finding_%d", i)
		label := fmt.Sprintf("[%s] %s", f.CheckID, f.Title)
		fillColor, borderColor := severityColors(f.Severity)
		fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
			findingID, label, fillColor, borderColor)
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteCloudAuditResult(result *analysis.CloudIAMAuditResult) error {
	fmt.Fprintln(d.w, "digraph CloudAudit {")
	fmt.Fprintln(d.w, "  rankdir=TB;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w)

	fmt.Fprintf(d.w, "  \"summary\" [label=\"Cloud IAM Audit\\nRoles: %d\\nFindings: %d\", shape=note, fillcolor=\"#f5f5f5\"];\n",
		result.AnalyzedRoles, len(result.Findings))

	for i, f := range result.Findings {
		findingID := fmt.Sprintf("finding_%d", i)
		label := fmt.Sprintf("[%s] %s\\n%s", f.Severity, f.Title, shortARN(f.RoleARN))
		fillColor, borderColor := severityColors(f.Severity)
		fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
			findingID, label, fillColor, borderColor)
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WritePodSecurityResult(result *analysis.PodSecurityResult) error {
	fmt.Fprintln(d.w, "digraph PodSecurityAudit {")
	fmt.Fprintln(d.w, "  rankdir=TB;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w)

	fmt.Fprintf(d.w, "  \"summary\" [label=\"Pod Security Audit\\nChecks: %d\\nFindings: %d\", shape=note, fillcolor=\"#f5f5f5\"];\n",
		len(result.ChecksRun), result.TotalFindings)

	for i, f := range result.Findings {
		findingID := fmt.Sprintf("finding_%d", i)
		label := fmt.Sprintf("[%s] %s\\n%d affected", f.CheckID, f.Title, len(f.Affected))
		fillColor, borderColor := severityColors(f.Severity)
		fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
			findingID, label, fillColor, borderColor)
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteNetworkPolicyResult(result *analysis.NetworkPolicyResult) error {
	fmt.Fprintln(d.w, "digraph NetworkPolicyAudit {")
	fmt.Fprintln(d.w, "  rankdir=TB;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w)

	fmt.Fprintf(d.w, "  \"summary\" [label=\"Network Policy Audit\\nPolicies: %d\\nFindings: %d\", shape=note, fillcolor=\"#f5f5f5\"];\n",
		result.Summary.TotalNetworkPolicies, result.TotalFindings)

	for i, f := range result.Findings {
		findingID := fmt.Sprintf("finding_%d", i)
		label := fmt.Sprintf("[%s] %s\\n%d affected", f.CheckID, f.Title, len(f.Affected))
		fillColor, borderColor := severityColors(f.Severity)
		fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
			findingID, label, fillColor, borderColor)
	}

	fmt.Fprintln(d.w, "}")
	return nil
}

func (d *DOTWriter) WriteAttackPathResults(results []*analysis.AttackPathResult) error {
	fmt.Fprintln(d.w, "digraph AttackPaths {")
	fmt.Fprintln(d.w, "  rankdir=LR;")
	fmt.Fprintln(d.w, "  node [shape=box, style=filled, fontname=\"Helvetica\"];")
	fmt.Fprintln(d.w, "  edge [fontname=\"Helvetica\", fontsize=9];")
	fmt.Fprintln(d.w, "  compound=true;")
	fmt.Fprintln(d.w)

	// Summary node
	summary := analysis.SummarizeAttackPaths(results)
	fmt.Fprintf(d.w, "  \"summary\" [label=\"Attack Paths\\nWorkloads: %d\\nPaths: %d\\nCritical: %d\", shape=note, fillcolor=\"#f5f5f5\"];\n",
		summary.WorkloadsWithPaths, summary.TotalPaths, summary.CriticalPaths)
	fmt.Fprintln(d.w)

	pathCounter := 0
	for _, r := range results {
		if r.SourceWorkload == nil || len(r.Paths) == 0 {
			continue
		}

		// Workload node
		workloadID := r.SourceWorkload.ID
		label := fmt.Sprintf("%s\\n%s/%s", r.SourceWorkload.Metadata.WorkloadKind, r.SourceWorkload.Namespace, r.SourceWorkload.Name)
		fmt.Fprintf(d.w, "  \"%s\" [label=\"%s\", fillcolor=\"#e3f2fd\", color=\"#1976d2\"];\n", workloadID, label)

		for _, path := range r.Paths {
			pathCounter++
			pathCluster := fmt.Sprintf("cluster_path_%d", pathCounter)

			// Create subgraph for each path
			fmt.Fprintf(d.w, "  subgraph %s {\n", pathCluster)
			fmt.Fprintf(d.w, "    label=\"%s\";\n", path.Name)
			fmt.Fprintf(d.w, "    style=dashed;\n")

			prevNodeID := workloadID
			for i, step := range path.Steps {
				stepID := fmt.Sprintf("step_%d_%d", pathCounter, i)
				stepLabel := fmt.Sprintf("Step %d\\n%s", step.StepNumber, step.Action)
				fillColor, borderColor := severityColors(step.Severity)
				fmt.Fprintf(d.w, "    \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\"];\n",
					stepID, stepLabel, fillColor, borderColor)

				if i > 0 {
					edgeColor := severityEdgeColor(step.Severity)
					fmt.Fprintf(d.w, "    \"%s\" -> \"%s\" [color=\"%s\", penwidth=2];\n",
						prevNodeID, stepID, edgeColor)
				}
				prevNodeID = stepID
			}

			// Objective node
			objectiveID := fmt.Sprintf("objective_%d", pathCounter)
			objFillColor, objBorderColor := severityColors(path.MaxSeverity)
			fmt.Fprintf(d.w, "    \"%s\" [label=\"%s\", fillcolor=\"%s\", color=\"%s\", shape=octagon];\n",
				objectiveID, path.Objective, objFillColor, objBorderColor)
			fmt.Fprintf(d.w, "    \"%s\" -> \"%s\" [color=\"%s\", penwidth=2, style=dashed];\n",
				prevNodeID, objectiveID, severityEdgeColor(path.MaxSeverity))

			fmt.Fprintln(d.w, "  }")

			// Connect workload to first step
			if len(path.Steps) > 0 {
				firstStepID := fmt.Sprintf("step_%d_0", pathCounter)
				fmt.Fprintf(d.w, "  \"%s\" -> \"%s\" [color=\"#666666\"];\n", workloadID, firstStepID)
			}
		}
		fmt.Fprintln(d.w)
	}

	fmt.Fprintln(d.w, "}")
	return nil
}
