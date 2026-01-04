package graph

type EdgeType string

const (
	EdgeUses    EdgeType = "uses"
	EdgeBinds   EdgeType = "binds"
	EdgeGrants  EdgeType = "grants"
	EdgeAssumes EdgeType = "assumes"
	EdgeAllows  EdgeType = "allows"
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

		if targetNode != nil && targetNode.Type == NodeK8sResource {
			switch targetNode.Metadata.ResourceKind {
			case "secrets":
				return SeverityCritical
			case "pods", "deployments", "daemonsets", "statefulsets":
				if hasDangerousVerb {
					return SeverityHigh
				}
			case "configmaps":
				if hasDangerousVerb {
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
