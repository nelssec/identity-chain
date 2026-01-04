package graph

type NodeType string

const (
	NodeWorkload       NodeType = "workload"
	NodeServiceAccount NodeType = "service_account"
	NodeRole           NodeType = "role"
	NodeK8sResource    NodeType = "k8s_resource"
	NodeCloudRole      NodeType = "cloud_role"
	NodeCloudResource  NodeType = "cloud_resource"
)

type Node struct {
	ID        string            `json:"id"`
	Type      NodeType          `json:"type"`
	Name      string            `json:"name"`
	Namespace string            `json:"namespace,omitempty"`
	Labels    map[string]string `json:"labels,omitempty"`
	Metadata  NodeMetadata      `json:"metadata,omitempty"`
}

type NodeMetadata struct {
	WorkloadKind      string        `json:"workload_kind,omitempty"`
	Replicas          int           `json:"replicas,omitempty"`
	CloudRoleARN      string        `json:"cloud_role_arn,omitempty"`
	GCPServiceAccount string        `json:"gcp_service_account,omitempty"`
	AzureManagedID    string        `json:"azure_managed_id,omitempty"`
	AutomountToken    bool          `json:"automount_token,omitempty"`
	IsClusterRole     bool          `json:"is_cluster_role,omitempty"`
	Rules             []Rule        `json:"rules,omitempty"`
	ResourceKind      string        `json:"resource_kind,omitempty"`
	Verbs             []string      `json:"verbs,omitempty"`
	CloudProvider     string        `json:"cloud_provider,omitempty"`
	PolicyARNs        []string      `json:"policy_arns,omitempty"`
	CloudPolicies     []CloudPolicy `json:"cloud_policies,omitempty"`
	ResourceType      string        `json:"resource_type,omitempty"`
	ResourceARN       string        `json:"resource_arn,omitempty"`
}

type CloudPolicy struct {
	Name       string            `json:"name"`
	ARN        string            `json:"arn,omitempty"`
	Type       string            `json:"type"`
	IsAdmin    bool              `json:"is_admin,omitempty"`
	Statements []PolicyStatement `json:"statements,omitempty"`
}

type PolicyStatement struct {
	Effect    string   `json:"effect"`
	Actions   []string `json:"actions"`
	Resources []string `json:"resources"`
}

type Rule struct {
	APIGroups     []string `json:"api_groups"`
	Resources     []string `json:"resources"`
	ResourceNames []string `json:"resource_names,omitempty"`
	Verbs         []string `json:"verbs"`
}

func NewNode(nodeType NodeType, namespace, name string) *Node {
	id := GenerateNodeID(nodeType, namespace, name)
	return &Node{
		ID:        id,
		Type:      nodeType,
		Name:      name,
		Namespace: namespace,
		Labels:    make(map[string]string),
	}
}

func GenerateNodeID(nodeType NodeType, namespace, name string) string {
	if namespace == "" {
		return string(nodeType) + ":" + name
	}
	return string(nodeType) + ":" + namespace + "/" + name
}

func (n *Node) IsClusterScoped() bool {
	return n.Namespace == ""
}

func (n *Node) HasCloudIdentity() bool {
	if n.Type != NodeServiceAccount {
		return false
	}
	return n.Metadata.CloudRoleARN != "" ||
		n.Metadata.GCPServiceAccount != "" ||
		n.Metadata.AzureManagedID != ""
}
