package output

import (
	"encoding/json"
	"io"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type JSONWriter struct {
	w       io.Writer
	encoder *json.Encoder
}

func NewJSONWriter(w io.Writer) *JSONWriter {
	encoder := json.NewEncoder(w)
	encoder.SetIndent("", "  ")
	return &JSONWriter{
		w:       w,
		encoder: encoder,
	}
}

func (j *JSONWriter) WriteBlastResult(result *analysis.BlastResult) error {
	return j.encoder.Encode(convertBlastResult(result))
}

func (j *JSONWriter) WriteBlastResults(results []*analysis.BlastResult) error {
	output := make([]blastResultJSON, 0, len(results))
	for _, r := range results {
		output = append(output, convertBlastResult(r))
	}
	return j.encoder.Encode(output)
}

func (j *JSONWriter) WriteGraph(g *graph.Graph) error {
	output := graphJSON{
		Nodes: g.AllNodes(),
		Edges: g.AllEdges(),
		Stats: g.Stats(),
	}
	return j.encoder.Encode(output)
}

func (j *JSONWriter) WriteStats(stats graph.GraphStats) error {
	return j.encoder.Encode(stats)
}

func (j *JSONWriter) WritePrivescResults(results []*analysis.PrivescResult) error {
	return j.encoder.Encode(results)
}

func (j *JSONWriter) WriteWhoCanResult(result *analysis.WhoCanResult) error {
	return j.encoder.Encode(result)
}

func (j *JSONWriter) WriteWhatCanResult(result *analysis.ReverseRBACResult) error {
	return j.encoder.Encode(result)
}

func (j *JSONWriter) WriteRBACAuditResult(result *analysis.RBACAuditResult) error {
	return j.encoder.Encode(result)
}

func (j *JSONWriter) WriteCloudAuditResult(result *analysis.CloudIAMAuditResult) error {
	return j.encoder.Encode(result)
}

type blastResultJSON struct {
	Workload        *nodeRef          `json:"workload,omitempty"`
	ServiceAccount  *nodeRef          `json:"service_account,omitempty"`
	K8sResources    []resourceJSON    `json:"k8s_resources,omitempty"`
	CloudRoles      []cloudRoleJSON   `json:"cloud_roles,omitempty"`
	BlastRadius     []string          `json:"blast_radius,omitempty"`
	TotalK8sPerms   int               `json:"total_k8s_permissions"`
	TotalCloudPerms int               `json:"total_cloud_permissions"`
	MaxSeverity     graph.Severity    `json:"max_severity"`
}

type nodeRef struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace,omitempty"`
	Kind      string `json:"kind,omitempty"`
}

type resourceJSON struct {
	Name      string         `json:"name"`
	Namespace string         `json:"namespace,omitempty"`
	Verbs     []string       `json:"verbs"`
	ViaRole   string         `json:"via_role"`
	Severity  graph.Severity `json:"severity"`
}

type cloudRoleJSON struct {
	Provider    string            `json:"provider"`
	RoleARN     string            `json:"role_arn"`
	Severity    graph.Severity    `json:"severity"`
	Policies    []cloudPolicyJSON `json:"policies,omitempty"`
	BlastRadius []string          `json:"blast_radius,omitempty"`
}

type cloudPolicyJSON struct {
	Name    string   `json:"name"`
	ARN     string   `json:"arn,omitempty"`
	IsAdmin bool     `json:"is_admin,omitempty"`
	Actions []string `json:"actions,omitempty"`
}

type graphJSON struct {
	Nodes []*graph.Node     `json:"nodes"`
	Edges []*graph.Edge     `json:"edges"`
	Stats graph.GraphStats  `json:"stats"`
}

func convertBlastResult(r *analysis.BlastResult) blastResultJSON {
	result := blastResultJSON{
		TotalK8sPerms:   r.TotalK8sPerms,
		TotalCloudPerms: r.TotalCloudPerms,
		MaxSeverity:     r.MaxSeverity,
	}

	if r.SourceWorkload != nil {
		result.Workload = &nodeRef{
			Name:      r.SourceWorkload.Name,
			Namespace: r.SourceWorkload.Namespace,
			Kind:      r.SourceWorkload.Metadata.WorkloadKind,
		}
	}

	if r.ServiceAccount != nil {
		result.ServiceAccount = &nodeRef{
			Name:      r.ServiceAccount.Name,
			Namespace: r.ServiceAccount.Namespace,
		}
	}

	for _, access := range r.K8sResources {
		result.K8sResources = append(result.K8sResources, resourceJSON{
			Name:      access.Resource.Name,
			Namespace: access.Resource.Namespace,
			Verbs:     access.Verbs,
			ViaRole:   access.ViaRole,
			Severity:  access.Severity,
		})
		blastDesc := describeK8sBlastRadius(access.Resource.Name, access.Resource.Namespace, access.Verbs, access.Severity)
		if blastDesc != "" {
			result.BlastRadius = append(result.BlastRadius, blastDesc)
		}
	}

	for _, access := range r.CloudRoles {
		crj := cloudRoleJSON{
			Provider:    access.Provider,
			RoleARN:     access.RoleARN,
			Severity:    access.Severity,
			BlastRadius: access.BlastRadius,
		}
		for _, p := range access.Policies {
			crj.Policies = append(crj.Policies, cloudPolicyJSON{
				Name:    p.Name,
				IsAdmin: p.IsAdmin,
				Actions: p.Actions,
			})
		}
		result.CloudRoles = append(result.CloudRoles, crj)
	}

	return result
}

func describeK8sBlastRadius(resourceName, namespace string, verbs []string, severity graph.Severity) string {
	hasRead := false
	hasWrite := false
	hasDelete := false
	hasAll := false

	for _, v := range verbs {
		switch v {
		case "*":
			hasAll = true
		case "get", "list", "watch":
			hasRead = true
		case "create", "update", "patch":
			hasWrite = true
		case "delete", "deletecollection":
			hasDelete = true
		}
	}

	scope := namespace
	if scope == "" {
		scope = "cluster-wide"
	}

	var accessLevel string
	if hasAll {
		accessLevel = "FULL control"
	} else if hasWrite && hasDelete {
		accessLevel = "Read/Write/Delete"
	} else if hasWrite {
		accessLevel = "Read/Write"
	} else if hasDelete {
		accessLevel = "Read/Delete"
	} else if hasRead {
		accessLevel = "Read"
	}

	switch resourceName {
	case "secrets":
		if hasAll || hasRead {
			return "Can READ ALL SECRETS in " + scope + " - potential credential exposure"
		}
		return accessLevel + " access to secrets in " + scope
	case "pods":
		if hasAll || hasWrite {
			return "Can CREATE/MODIFY PODS in " + scope + " - potential container injection"
		}
		return accessLevel + " access to pods in " + scope
	case "pods/exec":
		if hasWrite || hasAll {
			return "Can EXEC INTO PODS in " + scope + " - lateral movement risk"
		}
		return "Pod exec access in " + scope
	case "deployments", "daemonsets", "statefulsets":
		if hasWrite || hasAll {
			return "Can modify " + resourceName + " in " + scope + " - potential workload takeover"
		}
		return accessLevel + " access to " + resourceName + " in " + scope
	case "roles", "clusterroles", "rolebindings", "clusterrolebindings":
		if hasWrite || hasAll {
			return "Can MODIFY RBAC " + resourceName + " - PRIVILEGE ESCALATION RISK"
		}
		return accessLevel + " access to RBAC " + resourceName
	case "nodes":
		if hasAll || hasWrite {
			return "Can modify NODES - cluster infrastructure risk"
		}
		return accessLevel + " access to nodes"
	default:
		if severity == graph.SeverityCritical {
			return "CRITICAL: " + accessLevel + " access to " + resourceName + " in " + scope
		}
		return accessLevel + " access to " + resourceName + " in " + scope
	}
}
