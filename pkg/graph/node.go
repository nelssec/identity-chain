package graph

type NodeType string

const (
	NodeWorkload       NodeType = "workload"
	NodeServiceAccount NodeType = "service_account"
	NodeUser           NodeType = "user"
	NodeGroup          NodeType = "group"
	NodeRole           NodeType = "role"
	NodeK8sResource    NodeType = "k8s_resource"
	NodeCloudRole      NodeType = "cloud_role"
	NodeCloudResource  NodeType = "cloud_resource"
	NodeNetworkPolicy  NodeType = "network_policy"
	NodeService        NodeType = "service"
	NodeSCC            NodeType = "scc"
	NodeRoute          NodeType = "route"
	NodeOAuthClient    NodeType = "oauth_client"
	NodeBuildConfig    NodeType = "build_config"
	NodeProject        NodeType = "project"

	NodeSecret              NodeType = "secret"
	NodeExternalSecret      NodeType = "external_secret"
	NodeSecretProviderClass NodeType = "secret_provider_class"
	NodePeerAuthentication  NodeType = "peer_authentication"
	NodeAuthorizationPolicy NodeType = "authorization_policy"
	NodeConstraintTemplate  NodeType = "constraint_template"
	NodeConstraint          NodeType = "constraint"
	NodeClusterPolicy       NodeType = "cluster_policy"
	NodeOIDCProvider        NodeType = "oidc_provider"
	NodeIdentityProvider    NodeType = "identity_provider"
	NodeValidatingWebhook   NodeType = "validating_webhook"
	NodeMutatingWebhook     NodeType = "mutating_webhook"
)

type Node struct {
	ID          string            `json:"id"`
	Type        NodeType          `json:"type"`
	Name        string            `json:"name"`
	Namespace   string            `json:"namespace,omitempty"`
	Labels      map[string]string `json:"labels,omitempty"`
	Annotations map[string]string `json:"annotations,omitempty"`
	Metadata    NodeMetadata      `json:"metadata,omitempty"`
}

type NodeMetadata struct {
	WorkloadKind       string              `json:"workload_kind,omitempty"`
	Replicas           int                 `json:"replicas,omitempty"`
	CloudRoleARN       string              `json:"cloud_role_arn,omitempty"`
	GCPServiceAccount  string              `json:"gcp_service_account,omitempty"`
	AzureManagedID     string              `json:"azure_managed_id,omitempty"`
	AutomountToken     bool                `json:"automount_token,omitempty"`
	IsClusterRole      bool                `json:"is_cluster_role,omitempty"`
	IsAggregated       bool                `json:"is_aggregated,omitempty"`
	Rules              []Rule              `json:"rules,omitempty"`
	ResourceKind       string              `json:"resource_kind,omitempty"`
	Verbs              []string            `json:"verbs,omitempty"`
	CloudProvider      string              `json:"cloud_provider,omitempty"`
	PolicyARNs         []string            `json:"policy_arns,omitempty"`
	CloudPolicies      []CloudPolicy       `json:"cloud_policies,omitempty"`
	ResourceType       string              `json:"resource_type,omitempty"`
	ResourceARN        string              `json:"resource_arn,omitempty"`
	PodSecurityContext *PodSecurityContext `json:"pod_security_context,omitempty"`
	NetworkPolicy      *NetworkPolicyInfo  `json:"network_policy,omitempty"`
	ServiceInfo        *ServiceInfo        `json:"service_info,omitempty"`
	SCCInfo            *SCCInfo            `json:"scc_info,omitempty"`
	RouteInfo          *RouteInfo          `json:"route_info,omitempty"`
	OAuthClientInfo    *OAuthClientInfo    `json:"oauth_client_info,omitempty"`
	BuildConfigInfo    *BuildConfigInfo    `json:"build_config_info,omitempty"`
	ProjectInfo        *ProjectInfo        `json:"project_info,omitempty"`
	// Phase 3: projected volume token metadata
	TokenAudience            string `json:"token_audience,omitempty"`
	TokenExpirationSeconds   int64  `json:"token_expiration_seconds,omitempty"`
	// Phase 3: EKS Pod Identity webhook annotation
	EKSPodIdentityAssociation string `json:"eks_pod_identity_association,omitempty"`
}

type SCCInfo struct {
	Priority                 int      `json:"priority,omitempty"`
	AllowPrivilegedContainer bool     `json:"allow_privileged_container,omitempty"`
	AllowHostDirVolumePlugin bool     `json:"allow_host_dir_volume_plugin,omitempty"`
	AllowHostNetwork         bool     `json:"allow_host_network,omitempty"`
	AllowHostPorts           bool     `json:"allow_host_ports,omitempty"`
	AllowHostPID             bool     `json:"allow_host_pid,omitempty"`
	AllowHostIPC             bool     `json:"allow_host_ipc,omitempty"`
	AllowedCapabilities      []string `json:"allowed_capabilities,omitempty"`
	DefaultAddCapabilities   []string `json:"default_add_capabilities,omitempty"`
	RequiredDropCapabilities []string `json:"required_drop_capabilities,omitempty"`
	ReadOnlyRootFilesystem   bool     `json:"read_only_root_filesystem,omitempty"`
	RunAsUserType            string   `json:"run_as_user_type,omitempty"`
	SELinuxContextType       string   `json:"selinux_context_type,omitempty"`
	FSGroupType              string   `json:"fsgroup_type,omitempty"`
	SupplementalGroupsType   string   `json:"supplemental_groups_type,omitempty"`
	Volumes                  []string `json:"volumes,omitempty"`
	Users                    []string `json:"users,omitempty"`
	Groups                   []string `json:"groups,omitempty"`
	SeccompProfiles          []string `json:"seccomp_profiles,omitempty"`
	AllowPrivilegeEscalation *bool    `json:"allow_privilege_escalation,omitempty"`
}

type NetworkPolicyInfo struct {
	PodSelector    map[string]string   `json:"pod_selector,omitempty"`
	PolicyTypes    []string            `json:"policy_types,omitempty"`
	IngressRules   []NetworkPolicyRule `json:"ingress_rules,omitempty"`
	EgressRules    []NetworkPolicyRule `json:"egress_rules,omitempty"`
	AllowAllIngress bool               `json:"allow_all_ingress,omitempty"`
	AllowAllEgress  bool               `json:"allow_all_egress,omitempty"`
	DenyAllIngress  bool               `json:"deny_all_ingress,omitempty"`
	DenyAllEgress   bool               `json:"deny_all_egress,omitempty"`
}

type NetworkPolicyRule struct {
	FromPodSelector       map[string]string `json:"from_pod_selector,omitempty"`
	FromNamespaceSelector map[string]string `json:"from_namespace_selector,omitempty"`
	FromIPBlock           string            `json:"from_ip_block,omitempty"`
	ToPodSelector         map[string]string `json:"to_pod_selector,omitempty"`
	ToNamespaceSelector   map[string]string `json:"to_namespace_selector,omitempty"`
	ToIPBlock             string            `json:"to_ip_block,omitempty"`
	Ports                 []PolicyPort      `json:"ports,omitempty"`
}

type PolicyPort struct {
	Protocol string `json:"protocol,omitempty"`
	Port     string `json:"port,omitempty"`
}

type ServiceInfo struct {
	ServiceType   string            `json:"service_type,omitempty"`
	ClusterIP     string            `json:"cluster_ip,omitempty"`
	ExternalIPs   []string          `json:"external_ips,omitempty"`
	LoadBalancerIP string           `json:"load_balancer_ip,omitempty"`
	Ports         []ServicePort     `json:"ports,omitempty"`
	Selector      map[string]string `json:"selector,omitempty"`
}

type ServicePort struct {
	Name       string `json:"name,omitempty"`
	Port       int32  `json:"port"`
	TargetPort string `json:"target_port,omitempty"`
	NodePort   int32  `json:"node_port,omitempty"`
	Protocol   string `json:"protocol,omitempty"`
}

type PodSecurityContext struct {
	HostNetwork bool                     `json:"host_network,omitempty"`
	HostPID     bool                     `json:"host_pid,omitempty"`
	HostIPC     bool                     `json:"host_ipc,omitempty"`
	HostPaths   []string                 `json:"host_paths,omitempty"`
	Containers  []ContainerSecurityInfo  `json:"containers,omitempty"`
}

type ContainerSecurityInfo struct {
	Name                     string   `json:"name"`
	Image                    string   `json:"image,omitempty"`
	ImagePullPolicy          string   `json:"image_pull_policy,omitempty"`
	Privileged               bool     `json:"privileged,omitempty"`
	RunAsRoot                bool     `json:"run_as_root,omitempty"`
	AllowPrivilegeEscalation bool     `json:"allow_privilege_escalation,omitempty"`
	ReadOnlyRootFilesystem   bool     `json:"read_only_root_filesystem,omitempty"`
	Capabilities             []string `json:"capabilities,omitempty"`
	HostPorts                []int32  `json:"host_ports,omitempty"`
	SecretsInEnv             int      `json:"secrets_in_env,omitempty"`
	HasSecurityContext       bool     `json:"has_security_context,omitempty"`
	HasResourceLimits        bool     `json:"has_resource_limits,omitempty"`
	HasResourceRequests      bool     `json:"has_resource_requests,omitempty"`
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

type RouteInfo struct {
	Host            string `json:"host,omitempty"`
	Path            string `json:"path,omitempty"`
	TLSEnabled      bool   `json:"tls_enabled,omitempty"`
	TLSTermination  string `json:"tls_termination,omitempty"`
	InsecurePolicy  string `json:"insecure_policy,omitempty"`
	TargetKind      string `json:"target_kind,omitempty"`
	TargetName      string `json:"target_name,omitempty"`
	WildcardPolicy  string `json:"wildcard_policy,omitempty"`
}

type OAuthClientInfo struct {
	RedirectURIs      []string `json:"redirect_uris,omitempty"`
	GrantMethod       string   `json:"grant_method,omitempty"`
	Scopes            []string `json:"scopes,omitempty"`
	AccessTokenMaxAge int      `json:"access_token_max_age,omitempty"`
}

type BuildConfigInfo struct {
	StrategyType        string   `json:"strategy_type,omitempty"`
	Privileged          bool     `json:"privileged,omitempty"`
	ExposesDockerSocket bool     `json:"exposes_docker_socket,omitempty"`
	DockerfilePath      string   `json:"dockerfile_path,omitempty"`
	BuilderImage        string   `json:"builder_image,omitempty"`
	SourceType          string   `json:"source_type,omitempty"`
	GitURI              string   `json:"git_uri,omitempty"`
	SecretsUsed         []string `json:"secrets_used,omitempty"`
	OutputImage         string   `json:"output_image,omitempty"`
	PushSecret          string   `json:"push_secret,omitempty"`
	ServiceAccount      string   `json:"service_account,omitempty"`
}

type ProjectInfo struct {
	Name        string `json:"name"`
	DisplayName string `json:"display_name,omitempty"`
	Requester   string `json:"requester,omitempty"`
	Status      string `json:"status,omitempty"`
}
