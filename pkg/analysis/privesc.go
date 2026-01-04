package analysis

import (
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// PrivescVector represents a type of privilege escalation attack
type PrivescVector string

const (
	VectorBindRoles         PrivescVector = "bind_roles"
	VectorEscalateVerb      PrivescVector = "escalate_verb"
	VectorImpersonate       PrivescVector = "impersonate"
	VectorCreatePods        PrivescVector = "create_pods"
	VectorPatchPods         PrivescVector = "patch_pods"
	VectorExecPods          PrivescVector = "exec_pods"
	VectorCreateCSR         PrivescVector = "create_csr"
	VectorApproveCSR        PrivescVector = "approve_csr"
	VectorReadSecrets       PrivescVector = "read_secrets"
	VectorNodeProxy         PrivescVector = "node_proxy"
	VectorCreateTokens      PrivescVector = "create_tokens"
	VectorModifyWebhooks    PrivescVector = "modify_webhooks"
	VectorCloudIAMEscalate  PrivescVector = "cloud_iam_escalate"
)

// PrivescPath represents a privilege escalation path
type PrivescPath struct {
	SourceWorkload   *graph.Node
	ServiceAccount   *graph.Node
	Steps            []PrivescStep
	FinalPrivilege   string
	Severity         graph.Severity
	Description      string
	Mitigations      []string
	AffectsAllNodes  bool
	AffectsCluster   bool
}

// PrivescStep represents a single step in a privilege escalation path
type PrivescStep struct {
	StepNumber  int
	Vector      PrivescVector
	FromNode    *graph.Node
	ToNode      *graph.Node
	ViaRole     string
	Verbs       []string
	Resources   []string
	Description string
	Severity    graph.Severity
}

// PrivescResult holds all discovered privilege escalation paths
type PrivescResult struct {
	SourceNode       *graph.Node
	Paths            []PrivescPath
	DirectVectors    []DirectVector
	MaxSeverity      graph.Severity
	TotalPaths       int
	CriticalPaths    int
	CanReachAdmin    bool
	CanEscapeCluster bool
}

// DirectVector is a single-step privesc capability
type DirectVector struct {
	Vector      PrivescVector
	Role        *graph.Node
	Verbs       []string
	Resources   []string
	Severity    graph.Severity
	Description string
}

// VectorInfo provides details about each privilege escalation vector
type VectorInfo struct {
	Name        string
	Description string
	Severity    graph.Severity
	Resources   []string
	Verbs       []string
	APIGroups   []string
}

// KnownVectors defines all known privilege escalation vectors
var KnownVectors = map[PrivescVector]VectorInfo{
	VectorBindRoles: {
		Name:        "Bind Roles/ClusterRoles",
		Description: "Can bind any Role or ClusterRole to themselves, granting arbitrary permissions",
		Severity:    graph.SeverityCritical,
		Resources:   []string{"rolebindings", "clusterrolebindings"},
		Verbs:       []string{"create", "update", "patch"},
		APIGroups:   []string{"rbac.authorization.k8s.io"},
	},
	VectorEscalateVerb: {
		Name:        "Escalate Verb",
		Description: "Can create roles with permissions exceeding their own (bypasses RBAC escalation prevention)",
		Severity:    graph.SeverityCritical,
		Resources:   []string{"roles", "clusterroles"},
		Verbs:       []string{"escalate"},
		APIGroups:   []string{"rbac.authorization.k8s.io"},
	},
	VectorImpersonate: {
		Name:        "Impersonate Users/Groups",
		Description: "Can impersonate other users, groups, or service accounts including system:masters",
		Severity:    graph.SeverityCritical,
		Resources:   []string{"users", "groups", "serviceaccounts"},
		Verbs:       []string{"impersonate"},
		APIGroups:   []string{""},
	},
	VectorCreatePods: {
		Name:        "Create Pods with Arbitrary SA",
		Description: "Can create pods using any service account, inheriting their permissions",
		Severity:    graph.SeverityHigh,
		Resources:   []string{"pods"},
		Verbs:       []string{"create"},
		APIGroups:   []string{""},
	},
	VectorPatchPods: {
		Name:        "Patch/Update Pods",
		Description: "Can modify existing pods to inject containers or change configurations",
		Severity:    graph.SeverityHigh,
		Resources:   []string{"pods"},
		Verbs:       []string{"update", "patch"},
		APIGroups:   []string{""},
	},
	VectorExecPods: {
		Name:        "Exec into Pods",
		Description: "Can execute commands in pods, enabling lateral movement",
		Severity:    graph.SeverityHigh,
		Resources:   []string{"pods/exec"},
		Verbs:       []string{"create", "get"},
		APIGroups:   []string{""},
	},
	VectorCreateCSR: {
		Name:        "Create Certificate Signing Requests",
		Description: "Can create CSRs to obtain certificates for any identity",
		Severity:    graph.SeverityHigh,
		Resources:   []string{"certificatesigningrequests"},
		Verbs:       []string{"create"},
		APIGroups:   []string{"certificates.k8s.io"},
	},
	VectorApproveCSR: {
		Name:        "Approve Certificate Signing Requests",
		Description: "Can approve CSRs, issuing certificates for any identity",
		Severity:    graph.SeverityCritical,
		Resources:   []string{"certificatesigningrequests/approval"},
		Verbs:       []string{"update"},
		APIGroups:   []string{"certificates.k8s.io"},
	},
	VectorReadSecrets: {
		Name:        "Read All Secrets",
		Description: "Can read secrets cluster-wide, including SA tokens and credentials",
		Severity:    graph.SeverityCritical,
		Resources:   []string{"secrets"},
		Verbs:       []string{"get", "list", "watch"},
		APIGroups:   []string{""},
	},
	VectorNodeProxy: {
		Name:        "Node Proxy Access",
		Description: "Can access kubelet API on nodes, bypassing RBAC for pod access",
		Severity:    graph.SeverityCritical,
		Resources:   []string{"nodes/proxy"},
		Verbs:       []string{"create", "get"},
		APIGroups:   []string{""},
	},
	VectorCreateTokens: {
		Name:        "Create ServiceAccount Tokens",
		Description: "Can create tokens for any service account",
		Severity:    graph.SeverityCritical,
		Resources:   []string{"serviceaccounts/token"},
		Verbs:       []string{"create"},
		APIGroups:   []string{""},
	},
	VectorModifyWebhooks: {
		Name:        "Modify Admission Webhooks",
		Description: "Can modify admission webhooks to intercept/modify all API requests",
		Severity:    graph.SeverityCritical,
		Resources:   []string{"validatingwebhookconfigurations", "mutatingwebhookconfigurations"},
		Verbs:       []string{"create", "update", "patch"},
		APIGroups:   []string{"admissionregistration.k8s.io"},
	},
	VectorCloudIAMEscalate: {
		Name:        "Cloud IAM Escalation",
		Description: "Has cloud IAM permissions that allow privilege escalation (iam:*, PassRole, etc)",
		Severity:    graph.SeverityCritical,
		Resources:   []string{},
		Verbs:       []string{},
		APIGroups:   []string{},
	},
}

// FindPrivescPaths discovers privilege escalation paths from a given starting point
func FindPrivescPaths(g *graph.Graph, startNodeID string, maxDepth int) (*PrivescResult, error) {
	startNode := g.GetNode(startNodeID)
	if startNode == nil {
		return nil, nil
	}

	result := &PrivescResult{
		SourceNode:  startNode,
		MaxSeverity: graph.SeverityLow,
	}

	// Find the service account for this workload
	var saNode *graph.Node
	if startNode.Type == graph.NodeWorkload {
		for _, e := range g.GetOutEdges(startNodeID) {
			if e.Type == graph.EdgeUses {
				saNode = g.GetNode(e.To)
				break
			}
		}
	} else if startNode.Type == graph.NodeServiceAccount {
		saNode = startNode
	}

	if saNode == nil {
		return result, nil
	}

	// Collect all roles bound to this SA
	roles := collectBoundRoles(g, saNode.ID)

	// Check for direct privilege escalation vectors
	for _, role := range roles {
		vectors := detectDirectVectors(g, role)
		result.DirectVectors = append(result.DirectVectors, vectors...)
	}

	// Build multi-hop privilege escalation paths
	paths := findMultiHopPaths(g, saNode, roles, maxDepth)
	result.Paths = paths
	result.TotalPaths = len(paths)

	// Analyze results
	for _, p := range paths {
		if p.Severity == graph.SeverityCritical {
			result.CriticalPaths++
		}
		if p.AffectsCluster {
			result.CanReachAdmin = true
		}
		if p.AffectsAllNodes {
			result.CanEscapeCluster = true
		}
		updatePrivescMaxSeverity(result, p.Severity)
	}

	for _, v := range result.DirectVectors {
		updatePrivescMaxSeverity(result, v.Severity)
	}

	// Sort paths by severity
	sort.Slice(result.Paths, func(i, j int) bool {
		return severityRank[result.Paths[i].Severity] < severityRank[result.Paths[j].Severity]
	})

	return result, nil
}

// FindAllPrivescPaths analyzes all workloads in the graph
func FindAllPrivescPaths(g *graph.Graph, maxDepth int) ([]*PrivescResult, error) {
	workloads := g.GetNodesByType(graph.NodeWorkload)
	results := make([]*PrivescResult, 0, len(workloads))

	for _, w := range workloads {
		result, err := FindPrivescPaths(g, w.ID, maxDepth)
		if err != nil {
			continue
		}
		if result != nil && (len(result.DirectVectors) > 0 || len(result.Paths) > 0) {
			results = append(results, result)
		}
	}

	// Sort by severity
	sort.Slice(results, func(i, j int) bool {
		return severityRank[results[i].MaxSeverity] < severityRank[results[j].MaxSeverity]
	})

	return results, nil
}

func collectBoundRoles(g *graph.Graph, saID string) []*graph.Node {
	var roles []*graph.Node
	seen := make(map[string]bool)

	for _, e := range g.GetOutEdges(saID) {
		if e.Type == graph.EdgeBinds {
			role := g.GetNode(e.To)
			if role != nil && !seen[role.ID] {
				roles = append(roles, role)
				seen[role.ID] = true
			}
		}
	}

	return roles
}

func detectDirectVectors(g *graph.Graph, role *graph.Node) []DirectVector {
	var vectors []DirectVector

	for _, e := range g.GetOutEdges(role.ID) {
		if e.Type != graph.EdgeGrants {
			continue
		}

		resourceNode := g.GetNode(e.To)
		if resourceNode == nil {
			continue
		}

		resourceKind := resourceNode.Metadata.ResourceKind
		verbs := e.Metadata.Verbs
		apiGroup := resourceNode.Metadata.ResourceKind

		// Check each known vector
		for vectorType, info := range KnownVectors {
			if matchesVector(resourceKind, verbs, apiGroup, info) {
				vectors = append(vectors, DirectVector{
					Vector:      vectorType,
					Role:        role,
					Verbs:       verbs,
					Resources:   []string{resourceKind},
					Severity:    info.Severity,
					Description: info.Description,
				})
			}
		}

		// Check for wildcard access
		if resourceKind == "*" || containsString(verbs, "*") {
			vectors = append(vectors, DirectVector{
				Vector:      VectorBindRoles,
				Role:        role,
				Verbs:       verbs,
				Resources:   []string{resourceKind},
				Severity:    graph.SeverityCritical,
				Description: "Has wildcard permissions - can do anything",
			})
		}
	}

	return vectors
}

func matchesVector(resourceKind string, verbs []string, apiGroup string, info VectorInfo) bool {
	// Check if resource matches
	resourceMatch := false
	for _, r := range info.Resources {
		if resourceKind == r || resourceKind == "*" {
			resourceMatch = true
			break
		}
	}

	if !resourceMatch {
		return false
	}

	// Check if verb matches
	verbMatch := false
	for _, v := range verbs {
		if v == "*" {
			verbMatch = true
			break
		}
		for _, iv := range info.Verbs {
			if v == iv {
				verbMatch = true
				break
			}
		}
	}

	return verbMatch
}

func findMultiHopPaths(g *graph.Graph, sa *graph.Node, roles []*graph.Node, maxDepth int) []PrivescPath {
	var paths []PrivescPath

	// Check for pod creation -> different SA chain
	if canCreatePods(g, roles) {
		// This SA can create pods with any SA in its namespace
		// Find all other SAs in the same namespace
		allSAs := g.GetNodesByType(graph.NodeServiceAccount)
		for _, otherSA := range allSAs {
			if otherSA.ID == sa.ID {
				continue
			}
			if otherSA.Namespace != sa.Namespace && !hasClusterRole(roles) {
				continue
			}

			// Check if the other SA has higher privileges
			otherRoles := collectBoundRoles(g, otherSA.ID)
			for _, otherRole := range otherRoles {
				otherVectors := detectDirectVectors(g, otherRole)
				if len(otherVectors) > 0 {
					path := PrivescPath{
						ServiceAccount: sa,
						Steps: []PrivescStep{
							{
								StepNumber:  1,
								Vector:      VectorCreatePods,
								FromNode:    sa,
								ToNode:      otherSA,
								Description: "Create pod using service account " + otherSA.Namespace + "/" + otherSA.Name,
								Severity:    graph.SeverityHigh,
							},
						},
						FinalPrivilege:  otherVectors[0].Description,
						Severity:        otherVectors[0].Severity,
						Description:     "Can create pods to assume " + otherSA.Name + " which has " + otherVectors[0].Vector.String(),
						AffectsCluster:  otherRole.Metadata.IsClusterRole,
					}
					paths = append(paths, path)
				}
			}
		}
	}

	// Check for role binding -> arbitrary permissions chain
	if canBindRoles(g, roles) {
		path := PrivescPath{
			ServiceAccount: sa,
			Steps: []PrivescStep{
				{
					StepNumber:  1,
					Vector:      VectorBindRoles,
					FromNode:    sa,
					Description: "Create RoleBinding to bind cluster-admin to self",
					Severity:    graph.SeverityCritical,
				},
			},
			FinalPrivilege: "cluster-admin equivalent",
			Severity:       graph.SeverityCritical,
			Description:    "Can bind any role to themselves, achieving cluster-admin",
			AffectsCluster: true,
			Mitigations: []string{
				"Remove bind verb from RoleBindings/ClusterRoleBindings",
				"Use admission webhooks to prevent self-escalation",
			},
		}
		paths = append(paths, path)
	}

	// Check for impersonation -> system:masters chain
	if canImpersonate(g, roles) {
		path := PrivescPath{
			ServiceAccount: sa,
			Steps: []PrivescStep{
				{
					StepNumber:  1,
					Vector:      VectorImpersonate,
					FromNode:    sa,
					Description: "Impersonate system:masters group",
					Severity:    graph.SeverityCritical,
				},
			},
			FinalPrivilege: "cluster superuser (system:masters)",
			Severity:       graph.SeverityCritical,
			Description:    "Can impersonate system:masters group for full cluster access",
			AffectsCluster: true,
			Mitigations: []string{
				"Remove impersonate verb from users/groups",
				"Restrict impersonation to specific identities",
			},
		}
		paths = append(paths, path)
	}

	// Check for secrets access -> steal other SA tokens
	if canReadAllSecrets(g, roles) {
		path := PrivescPath{
			ServiceAccount: sa,
			Steps: []PrivescStep{
				{
					StepNumber:  1,
					Vector:      VectorReadSecrets,
					FromNode:    sa,
					Description: "Read service account tokens from secrets",
					Severity:    graph.SeverityCritical,
				},
			},
			FinalPrivilege: "Any service account in accessible namespaces",
			Severity:       graph.SeverityCritical,
			Description:    "Can read SA tokens from secrets to assume any identity",
			AffectsCluster: hasClusterRole(roles),
			Mitigations: []string{
				"Use bound service account tokens instead of secret-based tokens",
				"Restrict secrets access to specific secrets",
			},
		}
		paths = append(paths, path)
	}

	// Check for node/proxy access -> kubelet API
	if canAccessNodeProxy(g, roles) {
		path := PrivescPath{
			ServiceAccount: sa,
			Steps: []PrivescStep{
				{
					StepNumber:  1,
					Vector:      VectorNodeProxy,
					FromNode:    sa,
					Description: "Access kubelet API via nodes/proxy",
					Severity:    graph.SeverityCritical,
				},
			},
			FinalPrivilege: "Direct kubelet access on all nodes",
			Severity:       graph.SeverityCritical,
			Description:    "Can access kubelet API to read pod contents and exec into containers",
			AffectsAllNodes: true,
			AffectsCluster:  true,
			Mitigations: []string{
				"Remove nodes/proxy access",
				"Use pods/exec instead with proper RBAC",
			},
		}
		paths = append(paths, path)
	}

	// Check for CSR creation + approval
	canCreate := canCreateCSR(g, roles)
	canApprove := canApproveCSR(g, roles)
	if canCreate && canApprove {
		path := PrivescPath{
			ServiceAccount: sa,
			Steps: []PrivescStep{
				{
					StepNumber:  1,
					Vector:      VectorCreateCSR,
					FromNode:    sa,
					Description: "Create CSR for kubelet or system:masters",
					Severity:    graph.SeverityHigh,
				},
				{
					StepNumber:  2,
					Vector:      VectorApproveCSR,
					FromNode:    sa,
					Description: "Approve the CSR to issue certificate",
					Severity:    graph.SeverityCritical,
				},
			},
			FinalPrivilege: "Certificate for any identity",
			Severity:       graph.SeverityCritical,
			Description:    "Can create and approve CSRs to obtain certificates for any identity",
			AffectsCluster: true,
			Mitigations: []string{
				"Separate CSR creation and approval permissions",
				"Use admission webhooks to validate CSR requests",
			},
		}
		paths = append(paths, path)
	}

	return paths
}

// Helper functions to check for specific capabilities

func canCreatePods(g *graph.Graph, roles []*graph.Node) bool {
	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}
			if (resourceNode.Metadata.ResourceKind == "pods" || resourceNode.Metadata.ResourceKind == "*") &&
				(containsString(e.Metadata.Verbs, "create") || containsString(e.Metadata.Verbs, "*")) {
				return true
			}
		}
	}
	return false
}

func canBindRoles(g *graph.Graph, roles []*graph.Node) bool {
	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}
			kind := resourceNode.Metadata.ResourceKind
			if (kind == "rolebindings" || kind == "clusterrolebindings" || kind == "*") &&
				(containsString(e.Metadata.Verbs, "create") ||
					containsString(e.Metadata.Verbs, "update") ||
					containsString(e.Metadata.Verbs, "patch") ||
					containsString(e.Metadata.Verbs, "*")) {
				return true
			}
		}
	}
	return false
}

func canImpersonate(g *graph.Graph, roles []*graph.Node) bool {
	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}
			kind := resourceNode.Metadata.ResourceKind
			if (kind == "users" || kind == "groups" || kind == "serviceaccounts" || kind == "*") &&
				(containsString(e.Metadata.Verbs, "impersonate") || containsString(e.Metadata.Verbs, "*")) {
				return true
			}
		}
	}
	return false
}

func canReadAllSecrets(g *graph.Graph, roles []*graph.Node) bool {
	for _, role := range roles {
		// Only critical if cluster-scoped
		if !role.Metadata.IsClusterRole {
			continue
		}
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}
			if (resourceNode.Metadata.ResourceKind == "secrets" || resourceNode.Metadata.ResourceKind == "*") &&
				(containsString(e.Metadata.Verbs, "get") ||
					containsString(e.Metadata.Verbs, "list") ||
					containsString(e.Metadata.Verbs, "*")) {
				return true
			}
		}
	}
	return false
}

func canAccessNodeProxy(g *graph.Graph, roles []*graph.Node) bool {
	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}
			kind := resourceNode.Metadata.ResourceKind
			if (kind == "nodes/proxy" || kind == "*") &&
				(containsString(e.Metadata.Verbs, "create") ||
					containsString(e.Metadata.Verbs, "get") ||
					containsString(e.Metadata.Verbs, "*")) {
				return true
			}
		}
	}
	return false
}

func canCreateCSR(g *graph.Graph, roles []*graph.Node) bool {
	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}
			if (resourceNode.Metadata.ResourceKind == "certificatesigningrequests" || resourceNode.Metadata.ResourceKind == "*") &&
				(containsString(e.Metadata.Verbs, "create") || containsString(e.Metadata.Verbs, "*")) {
				return true
			}
		}
	}
	return false
}

func canApproveCSR(g *graph.Graph, roles []*graph.Node) bool {
	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}
			kind := resourceNode.Metadata.ResourceKind
			if (kind == "certificatesigningrequests/approval" || kind == "*") &&
				(containsString(e.Metadata.Verbs, "update") || containsString(e.Metadata.Verbs, "*")) {
				return true
			}
		}
	}
	return false
}

func hasClusterRole(roles []*graph.Node) bool {
	for _, r := range roles {
		if r.Metadata.IsClusterRole {
			return true
		}
	}
	return false
}

func containsString(slice []string, s string) bool {
	for _, item := range slice {
		if item == s {
			return true
		}
	}
	return false
}

func updatePrivescMaxSeverity(r *PrivescResult, s graph.Severity) {
	if severityValue[s] > severityValue[r.MaxSeverity] {
		r.MaxSeverity = s
	}
}

func (v PrivescVector) String() string {
	if info, ok := KnownVectors[v]; ok {
		return info.Name
	}
	return string(v)
}

// PrivescSummary provides a summary of privilege escalation findings
type PrivescSummary struct {
	TotalWorkloads       int
	WorkloadsWithPrivesc int
	CriticalPaths        int
	HighPaths            int
	TopVectors           []VectorCount
	AffectedNamespaces   []string
}

type VectorCount struct {
	Vector PrivescVector
	Count  int
}

// SummarizePrivescResults creates a summary from multiple results
func SummarizePrivescResults(results []*PrivescResult) *PrivescSummary {
	summary := &PrivescSummary{}

	vectorCounts := make(map[PrivescVector]int)
	namespaces := make(map[string]bool)

	for _, r := range results {
		if len(r.DirectVectors) > 0 || len(r.Paths) > 0 {
			summary.WorkloadsWithPrivesc++
			if r.SourceNode != nil && r.SourceNode.Namespace != "" {
				namespaces[r.SourceNode.Namespace] = true
			}
		}

		for _, v := range r.DirectVectors {
			vectorCounts[v.Vector]++
			if v.Severity == graph.SeverityCritical {
				summary.CriticalPaths++
			} else if v.Severity == graph.SeverityHigh {
				summary.HighPaths++
			}
		}

		for _, p := range r.Paths {
			if len(p.Steps) > 0 {
				vectorCounts[p.Steps[0].Vector]++
			}
			if p.Severity == graph.SeverityCritical {
				summary.CriticalPaths++
			} else if p.Severity == graph.SeverityHigh {
				summary.HighPaths++
			}
		}
	}

	for v, count := range vectorCounts {
		summary.TopVectors = append(summary.TopVectors, VectorCount{Vector: v, Count: count})
	}
	sort.Slice(summary.TopVectors, func(i, j int) bool {
		return summary.TopVectors[i].Count > summary.TopVectors[j].Count
	})

	for ns := range namespaces {
		summary.AffectedNamespaces = append(summary.AffectedNamespaces, ns)
	}
	sort.Strings(summary.AffectedNamespaces)

	return summary
}

// CanEscalateToClusterAdmin checks if there's any path to cluster-admin equivalent
func CanEscalateToClusterAdmin(g *graph.Graph, startNodeID string) (bool, *PrivescPath) {
	result, err := FindPrivescPaths(g, startNodeID, 3)
	if err != nil || result == nil {
		return false, nil
	}

	for _, p := range result.Paths {
		if p.AffectsCluster && p.Severity == graph.SeverityCritical {
			return true, &p
		}
	}

	for _, v := range result.DirectVectors {
		if v.Severity == graph.SeverityCritical {
			path := PrivescPath{
				ServiceAccount: result.SourceNode,
				Steps: []PrivescStep{{
					Vector:      v.Vector,
					Description: v.Description,
					Severity:    v.Severity,
				}},
				FinalPrivilege: v.Description,
				Severity:       v.Severity,
				AffectsCluster: true,
			}
			return true, &path
		}
	}

	return false, nil
}

// DetectPodCreationAbuse checks for dangerous pod specifications that could be created
func DetectPodCreationAbuse(g *graph.Graph, saNode *graph.Node) []string {
	var risks []string
	roles := collectBoundRoles(g, saNode.ID)

	if !canCreatePods(g, roles) {
		return risks
	}

	// If they can create pods, check what dangerous things they could configure
	risks = append(risks, "Can create pods with privileged containers")
	risks = append(risks, "Can create pods with hostPath mounts")
	risks = append(risks, "Can create pods with hostNetwork/hostPID/hostIPC")
	risks = append(risks, "Can create pods using any ServiceAccount")

	// Check if they can also create deployments/daemonsets
	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}
			kind := strings.ToLower(resourceNode.Metadata.ResourceKind)
			if containsString(e.Metadata.Verbs, "create") || containsString(e.Metadata.Verbs, "*") {
				switch kind {
				case "deployments":
					risks = append(risks, "Can create Deployments (persistent privileged workloads)")
				case "daemonsets":
					risks = append(risks, "Can create DaemonSets (run on ALL nodes)")
				case "jobs", "cronjobs":
					risks = append(risks, "Can create Jobs/CronJobs (scheduled privileged execution)")
				}
			}
		}
	}

	return risks
}
