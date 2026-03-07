package graph

type EdgeType string

const (
	EdgeUses       EdgeType = "uses"
	EdgeBinds      EdgeType = "binds"
	EdgeGrants     EdgeType = "grants"
	EdgeAssumes    EdgeType = "assumes"
	EdgeAllows     EdgeType = "allows"
	EdgeAggregates EdgeType = "aggregates"
)

type Edge struct {
	ID       string   `json:"id"`
	Type     EdgeType `json:"type"`
	From     string   `json:"from"`
	To       string   `json:"to"`
	Metadata EdgeMeta `json:"metadata,omitempty"`
}

type EdgeMeta struct {
	BindingName      string   `json:"binding_name,omitempty"`
	BindingNamespace string   `json:"binding_namespace,omitempty"`
	IsClusterBinding bool     `json:"is_cluster_binding,omitempty"`
	Verbs            []string `json:"verbs,omitempty"`
	ResourceNames    []string `json:"resource_names,omitempty"`
	CloudProvider    string   `json:"cloud_provider,omitempty"`
	RoleARN          string   `json:"role_arn,omitempty"`
	Actions          []string `json:"actions,omitempty"`
	Conditions       []string `json:"conditions,omitempty"`
	Severity         Severity `json:"severity,omitempty"`
	// AggregationLabel is set on EdgeAggregates edges to record which label
	// selector triggered the aggregation relationship.
	AggregationLabel string `json:"aggregation_label,omitempty"`
}

func NewEdge(edgeType EdgeType, from, to string) *Edge {
	return &Edge{
		ID:   GenerateEdgeID(edgeType, from, to),
		Type: edgeType,
		From: from,
		To:   to,
	}
}

func GenerateEdgeID(edgeType EdgeType, from, to string) string {
	return string(edgeType) + ":" + from + "->" + to
}

type Severity string

const (
	SeverityCritical Severity = "critical"
	SeverityHigh     Severity = "high"
	SeverityMedium   Severity = "medium"
	SeverityLow      Severity = "low"
)

func ClassifyEdgeSeverity(e *Edge, targetNode *Node) Severity {
	if e.Type == EdgeGrants {
		hasDangerousVerb := false
		for _, v := range e.Metadata.Verbs {
			switch v {
			case "*", "create", "update", "patch", "delete":
				hasDangerousVerb = true
			}
		}

		// When resourceNames are specified the permission is tightly scoped to
		// particular named resources, which reduces the blast radius.
		// We drop severity by one level for non-wildcard name-restricted rules.
		isScopedByName := len(e.Metadata.ResourceNames) > 0

		if targetNode != nil && targetNode.Type == NodeK8sResource {
			switch targetNode.Metadata.ResourceKind {
			case "secrets":
				if isScopedByName {
					// Scoped to specific secret(s) – still high but not critical.
					return SeverityHigh
				}
				return SeverityCritical
			case "pods", "deployments", "daemonsets", "statefulsets":
				if hasDangerousVerb {
					if isScopedByName {
						return SeverityMedium
					}
					return SeverityHigh
				}
			case "configmaps":
				if hasDangerousVerb {
					if isScopedByName {
						return SeverityLow
					}
					return SeverityMedium
				}
			}
		}
	}

	if e.Type == EdgeAssumes {
		return SeverityHigh
	}

	if e.Type == EdgeAllows {
		for _, action := range e.Metadata.Actions {
			if action == "*" || action == "*:*" {
				return SeverityCritical
			}
		}
		return SeverityHigh
	}

	return SeverityLow
}
