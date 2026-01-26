package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type IdentityChainOptions struct {
	Namespace      string
	WorkloadRef    string
	IncludeCloud   bool
	MaxDepth       int
	OutputFormat   string
}

type IdentityChainResult struct {
	Chains               []IdentityChain       `json:"chains"`
	TotalWorkloads       int                   `json:"total_workloads"`
	ChainsWithCloudAccess int                  `json:"chains_with_cloud_access"`
	CrossAccountChains   int                   `json:"cross_account_chains"`
	HighRiskChains       []IdentityChain       `json:"high_risk_chains"`
	Summary              IdentityChainSummary  `json:"summary"`
	DOTOutput            string                `json:"dot_output,omitempty"`
	MermaidOutput        string                `json:"mermaid_output,omitempty"`
}

type IdentityChain struct {
	WorkloadID           string                 `json:"workload_id"`
	WorkloadName         string                 `json:"workload_name"`
	WorkloadNamespace    string                 `json:"workload_namespace"`
	WorkloadKind         string                 `json:"workload_kind"`
	ServiceAccount       *ChainServiceAccount   `json:"service_account,omitempty"`
	K8sRoles             []ChainK8sRole         `json:"k8s_roles,omitempty"`
	CloudRoles           []ChainCloudRole       `json:"cloud_roles,omitempty"`
	CloudResources       []ChainCloudResource   `json:"cloud_resources,omitempty"`
	EffectivePermissions *EffectivePermissions  `json:"effective_permissions,omitempty"`
	RiskScore            int                    `json:"risk_score"`
	RiskLevel            string                 `json:"risk_level"`
	ChainDepth           int                    `json:"chain_depth"`
	HasCloudAccess       bool                   `json:"has_cloud_access"`
	IsCrossAccount       bool                   `json:"is_cross_account"`
	TrustChain           []TrustRelationship    `json:"trust_chain,omitempty"`
}

type ChainServiceAccount struct {
	Name             string   `json:"name"`
	Namespace        string   `json:"namespace"`
	AutomountToken   bool     `json:"automount_token"`
	CloudRoleARN     string   `json:"cloud_role_arn,omitempty"`
	GCPServiceAccount string  `json:"gcp_service_account,omitempty"`
	AzureManagedID   string   `json:"azure_managed_id,omitempty"`
	CloudProvider    string   `json:"cloud_provider,omitempty"`
}

type ChainK8sRole struct {
	Name          string       `json:"name"`
	Namespace     string       `json:"namespace,omitempty"`
	IsClusterRole bool         `json:"is_cluster_role"`
	Rules         []graph.Rule `json:"rules,omitempty"`
	ViaBinding    string       `json:"via_binding"`
}

type ChainCloudRole struct {
	Provider      string               `json:"provider"`
	RoleARN       string               `json:"role_arn,omitempty"`
	RoleName      string               `json:"role_name,omitempty"`
	AccountID     string               `json:"account_id,omitempty"`
	Region        string               `json:"region,omitempty"`
	IsAdmin       bool                 `json:"is_admin,omitempty"`
	Policies      []ChainCloudPolicy   `json:"policies,omitempty"`
	AssumedBy     []string             `json:"assumed_by,omitempty"`
	CanAssumeRoles []string            `json:"can_assume_roles,omitempty"`
}

type ChainCloudPolicy struct {
	Name       string `json:"name"`
	ARN        string `json:"arn,omitempty"`
	Type       string `json:"type"`
	IsAdmin    bool   `json:"is_admin,omitempty"`
	Permissions int   `json:"permissions,omitempty"`
}

type ChainCloudResource struct {
	Provider     string   `json:"provider"`
	ResourceType string   `json:"resource_type"`
	ResourceARN  string   `json:"resource_arn,omitempty"`
	ResourceName string   `json:"resource_name,omitempty"`
	AccessLevel  string   `json:"access_level"`
	Actions      []string `json:"actions,omitempty"`
}

type TrustRelationship struct {
	From            string `json:"from"`
	To              string `json:"to"`
	TrustType       string `json:"trust_type"`
	Condition       string `json:"condition,omitempty"`
	CrossAccount    bool   `json:"cross_account"`
	SourceAccountID string `json:"source_account_id,omitempty"`
	TargetAccountID string `json:"target_account_id,omitempty"`
}

type EffectivePermissions struct {
	K8sPermissions   []K8sPermission   `json:"k8s_permissions"`
	CloudPermissions []CloudPermission `json:"cloud_permissions"`
	CanAccessSecrets bool              `json:"can_access_secrets"`
	HasClusterAdmin  bool              `json:"has_cluster_admin"`
	HasCloudAdmin    bool              `json:"has_cloud_admin"`
}

type K8sPermission struct {
	APIGroup     string   `json:"api_group"`
	Resources    []string `json:"resources"`
	Verbs        []string `json:"verbs"`
	Namespaces   []string `json:"namespaces,omitempty"`
	IsWildcard   bool     `json:"is_wildcard"`
	ViaRole      string   `json:"via_role"`
}

type CloudPermission struct {
	Provider   string   `json:"provider"`
	Service    string   `json:"service"`
	Actions    []string `json:"actions"`
	Resources  []string `json:"resources"`
	IsWildcard bool     `json:"is_wildcard"`
	ViaPolicy  string   `json:"via_policy"`
}

type IdentityChainSummary struct {
	TotalChains          int            `json:"total_chains"`
	ChainsWithCloudAccess int           `json:"chains_with_cloud_access"`
	CrossAccountChains   int            `json:"cross_account_chains"`
	ChainsWithAdmin      int            `json:"chains_with_admin"`
	AverageChainDepth    float64        `json:"average_chain_depth"`
	MaxChainDepth        int            `json:"max_chain_depth"`
	ByCloudProvider      map[string]int `json:"by_cloud_provider"`
	ByRiskLevel          map[string]int `json:"by_risk_level"`
}

func AnalyzeIdentityChains(g *graph.Graph, opts IdentityChainOptions) *IdentityChainResult {
	result := &IdentityChainResult{
		Chains:         []IdentityChain{},
		HighRiskChains: []IdentityChain{},
		Summary: IdentityChainSummary{
			ByCloudProvider: make(map[string]int),
			ByRiskLevel:     make(map[string]int),
		},
	}

	if opts.MaxDepth == 0 {
		opts.MaxDepth = 10
	}

	workloads := g.GetNodesByType(graph.NodeWorkload)
	result.TotalWorkloads = len(workloads)

	for _, workload := range workloads {
		if opts.Namespace != "" && workload.Namespace != opts.Namespace {
			continue
		}

		if opts.WorkloadRef != "" {
			_, ns, name := graph.ParseWorkloadRef(opts.WorkloadRef, opts.Namespace)
			if workload.Namespace != ns || workload.Name != name {
				continue
			}
		}

		chain := traceIdentityChain(g, workload, opts.MaxDepth)
		result.Chains = append(result.Chains, chain)

		if chain.HasCloudAccess {
			result.ChainsWithCloudAccess++
		}
		if chain.IsCrossAccount {
			result.CrossAccountChains++
		}
		if chain.RiskScore >= 70 {
			result.HighRiskChains = append(result.HighRiskChains, chain)
		}

		result.Summary.ByRiskLevel[chain.RiskLevel]++
		if chain.ServiceAccount != nil && chain.ServiceAccount.CloudProvider != "" {
			result.Summary.ByCloudProvider[chain.ServiceAccount.CloudProvider]++
		}
	}

	sort.Slice(result.Chains, func(i, j int) bool {
		return result.Chains[i].RiskScore > result.Chains[j].RiskScore
	})

	calculateChainSummary(result)

	if opts.OutputFormat == "dot" || opts.OutputFormat == "all" {
		result.DOTOutput = generateDOTOutput(result.Chains)
	}
	if opts.OutputFormat == "mermaid" || opts.OutputFormat == "all" {
		result.MermaidOutput = generateMermaidOutput(result.Chains)
	}

	return result
}

func traceIdentityChain(g *graph.Graph, workload *graph.Node, maxDepth int) IdentityChain {
	chain := IdentityChain{
		WorkloadID:        workload.ID,
		WorkloadName:      workload.Name,
		WorkloadNamespace: workload.Namespace,
		WorkloadKind:      workload.Metadata.WorkloadKind,
		K8sRoles:          []ChainK8sRole{},
		CloudRoles:        []ChainCloudRole{},
		CloudResources:    []ChainCloudResource{},
		TrustChain:        []TrustRelationship{},
	}

	chain.ChainDepth = 1

	outEdges := g.GetOutEdges(workload.ID)
	for _, edge := range outEdges {
		if edge.Type == graph.EdgeUses {
			saNode := g.GetNode(edge.To)
			if saNode != nil && saNode.Type == graph.NodeServiceAccount {
				chain.ServiceAccount = extractServiceAccountInfo(saNode)
				chain.ChainDepth++

				if chain.ServiceAccount.CloudRoleARN != "" ||
				   chain.ServiceAccount.GCPServiceAccount != "" ||
				   chain.ServiceAccount.AzureManagedID != "" {
					chain.HasCloudAccess = true
				}

				traceK8sRoles(g, saNode, &chain, maxDepth)
				traceCloudRoles(g, saNode, &chain, maxDepth)
				break
			}
		}
	}

	chain.EffectivePermissions = calculateEffectivePermissions(&chain)

	chain.RiskScore = calculateChainRiskScore(&chain)
	chain.RiskLevel = getRiskLevel(chain.RiskScore)

	return chain
}

func extractServiceAccountInfo(sa *graph.Node) *ChainServiceAccount {
	info := &ChainServiceAccount{
		Name:           sa.Name,
		Namespace:      sa.Namespace,
		AutomountToken: sa.Metadata.AutomountToken,
	}

	if sa.Metadata.CloudRoleARN != "" {
		info.CloudRoleARN = sa.Metadata.CloudRoleARN
		info.CloudProvider = "aws"
	}
	if sa.Metadata.GCPServiceAccount != "" {
		info.GCPServiceAccount = sa.Metadata.GCPServiceAccount
		info.CloudProvider = "gcp"
	}
	if sa.Metadata.AzureManagedID != "" {
		info.AzureManagedID = sa.Metadata.AzureManagedID
		info.CloudProvider = "azure"
	}

	return info
}

func traceK8sRoles(g *graph.Graph, sa *graph.Node, chain *IdentityChain, maxDepth int) {
	inEdges := g.GetInEdges(sa.ID)
	visited := make(map[string]bool)

	for _, edge := range inEdges {
		if edge.Type == graph.EdgeBinds {
			bindingNode := g.GetNode(edge.From)
			if bindingNode == nil {
				continue
			}

			bindingEdges := g.GetOutEdges(bindingNode.ID)
			for _, be := range bindingEdges {
				if be.Type == graph.EdgeGrants {
					roleNode := g.GetNode(be.To)
					if roleNode != nil && roleNode.Type == graph.NodeRole {
						if visited[roleNode.ID] {
							continue
						}
						visited[roleNode.ID] = true

						roleInfo := ChainK8sRole{
							Name:          roleNode.Name,
							Namespace:     roleNode.Namespace,
							IsClusterRole: roleNode.Metadata.IsClusterRole,
							Rules:         roleNode.Metadata.Rules,
							ViaBinding:    bindingNode.Name,
						}
						chain.K8sRoles = append(chain.K8sRoles, roleInfo)
						chain.ChainDepth++
					}
				}
			}
		}
	}
}

func traceCloudRoles(g *graph.Graph, sa *graph.Node, chain *IdentityChain, maxDepth int) {
	saEdges := g.GetOutEdges(sa.ID)
	visited := make(map[string]bool)

	for _, edge := range saEdges {
		if edge.Type == graph.EdgeAssumes {
			cloudRoleNode := g.GetNode(edge.To)
			if cloudRoleNode != nil && cloudRoleNode.Type == graph.NodeCloudRole {
				traceCloudRoleChain(g, cloudRoleNode, chain, visited, maxDepth, 0)
			}
		}
	}

	for _, edge := range saEdges {
		if edge.Type == graph.EdgeAllows {
			resourceNode := g.GetNode(edge.To)
			if resourceNode != nil && resourceNode.Type == graph.NodeCloudResource {
				extractCloudResource(resourceNode, chain)
			}
		}
	}
}

func traceCloudRoleChain(g *graph.Graph, roleNode *graph.Node, chain *IdentityChain, visited map[string]bool, maxDepth, currentDepth int) {
	if visited[roleNode.ID] || currentDepth >= maxDepth {
		return
	}
	visited[roleNode.ID] = true

	roleInfo := extractCloudRoleInfo(roleNode)
	chain.CloudRoles = append(chain.CloudRoles, roleInfo)
	chain.ChainDepth++

	if roleInfo.IsAdmin {
		chain.HasCloudAccess = true
	}

	roleEdges := g.GetOutEdges(roleNode.ID)
	for _, edge := range roleEdges {
		if edge.Type == graph.EdgeAssumes {
			targetNode := g.GetNode(edge.To)
			if targetNode != nil && targetNode.Type == graph.NodeCloudRole {
				sourceAccount := extractAccountID(roleInfo.RoleARN)
				targetAccount := extractAccountID(targetNode.Metadata.CloudRoleARN)

				if sourceAccount != "" && targetAccount != "" && sourceAccount != targetAccount {
					chain.IsCrossAccount = true
					chain.TrustChain = append(chain.TrustChain, TrustRelationship{
						From:            roleInfo.RoleName,
						To:              targetNode.Name,
						TrustType:       "assume_role",
						CrossAccount:    true,
						SourceAccountID: sourceAccount,
						TargetAccountID: targetAccount,
					})
				}

				traceCloudRoleChain(g, targetNode, chain, visited, maxDepth, currentDepth+1)
			}
		}

		if edge.Type == graph.EdgeAllows {
			resourceNode := g.GetNode(edge.To)
			if resourceNode != nil && resourceNode.Type == graph.NodeCloudResource {
				extractCloudResource(resourceNode, chain)
			}
		}
	}
}

func extractCloudRoleInfo(node *graph.Node) ChainCloudRole {
	role := ChainCloudRole{
		Provider: node.Metadata.CloudProvider,
		RoleARN:  node.Metadata.CloudRoleARN,
		RoleName: node.Name,
		Policies: []ChainCloudPolicy{},
	}

	role.AccountID = extractAccountID(role.RoleARN)

	for _, policy := range node.Metadata.CloudPolicies {
		cp := ChainCloudPolicy{
			Name:    policy.Name,
			ARN:     policy.ARN,
			Type:    policy.Type,
			IsAdmin: policy.IsAdmin,
		}
		if policy.IsAdmin {
			role.IsAdmin = true
		}
		cp.Permissions = len(policy.Statements)
		role.Policies = append(role.Policies, cp)
	}

	return role
}

func extractCloudResource(node *graph.Node, chain *IdentityChain) {
	resource := ChainCloudResource{
		Provider:     node.Metadata.CloudProvider,
		ResourceType: node.Metadata.ResourceType,
		ResourceARN:  node.Metadata.ResourceARN,
		ResourceName: node.Name,
		AccessLevel:  "read",
	}

	for _, existing := range chain.CloudResources {
		if existing.ResourceARN == resource.ResourceARN {
			return
		}
	}

	chain.CloudResources = append(chain.CloudResources, resource)
	chain.HasCloudAccess = true
}

func extractAccountID(arn string) string {
	if !strings.HasPrefix(arn, "arn:aws:") {
		return ""
	}
	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func calculateEffectivePermissions(chain *IdentityChain) *EffectivePermissions {
	perms := &EffectivePermissions{
		K8sPermissions:   []K8sPermission{},
		CloudPermissions: []CloudPermission{},
	}

	for _, role := range chain.K8sRoles {
		for _, rule := range role.Rules {
			perm := K8sPermission{
				Verbs:    rule.Verbs,
				ViaRole:  role.Name,
			}

			if len(rule.APIGroups) > 0 {
				perm.APIGroup = rule.APIGroups[0]
			}
			perm.Resources = rule.Resources

			for _, verb := range rule.Verbs {
				if verb == "*" {
					perm.IsWildcard = true
				}
			}
			for _, res := range rule.Resources {
				if res == "*" {
					perm.IsWildcard = true
				}
				if res == "secrets" {
					perms.CanAccessSecrets = true
				}
			}

			if role.IsClusterRole && perm.IsWildcard {
				for _, verb := range rule.Verbs {
					if verb == "*" || verb == "get" || verb == "list" || verb == "watch" || verb == "create" || verb == "update" || verb == "delete" {
						for _, res := range rule.Resources {
							if res == "*" {
								perms.HasClusterAdmin = true
							}
						}
					}
				}
			}

			perms.K8sPermissions = append(perms.K8sPermissions, perm)
		}
	}

	for _, role := range chain.CloudRoles {
		if role.IsAdmin {
			perms.HasCloudAdmin = true
		}

		for _, policy := range role.Policies {
			if policy.IsAdmin {
				perms.HasCloudAdmin = true
			}
		}
	}

	return perms
}

func calculateChainRiskScore(chain *IdentityChain) int {
	score := 0

	if chain.HasCloudAccess {
		score += 20
	}

	if chain.IsCrossAccount {
		score += 25
	}

	if chain.EffectivePermissions != nil {
		if chain.EffectivePermissions.HasClusterAdmin {
			score += 40
		}
		if chain.EffectivePermissions.HasCloudAdmin {
			score += 35
		}
		if chain.EffectivePermissions.CanAccessSecrets {
			score += 15
		}
	}

	for _, role := range chain.CloudRoles {
		if role.IsAdmin {
			score += 30
		}
	}

	if chain.ChainDepth > 5 {
		score += 10
	}

	if score > 100 {
		score = 100
	}

	return score
}

func getRiskLevel(score int) string {
	if score >= 80 {
		return "critical"
	}
	if score >= 60 {
		return "high"
	}
	if score >= 40 {
		return "medium"
	}
	return "low"
}

func calculateChainSummary(result *IdentityChainResult) {
	result.Summary.TotalChains = len(result.Chains)
	result.Summary.ChainsWithCloudAccess = result.ChainsWithCloudAccess
	result.Summary.CrossAccountChains = result.CrossAccountChains

	totalDepth := 0
	maxDepth := 0
	adminCount := 0

	for _, chain := range result.Chains {
		totalDepth += chain.ChainDepth
		if chain.ChainDepth > maxDepth {
			maxDepth = chain.ChainDepth
		}
		if chain.EffectivePermissions != nil {
			if chain.EffectivePermissions.HasClusterAdmin || chain.EffectivePermissions.HasCloudAdmin {
				adminCount++
			}
		}
	}

	if len(result.Chains) > 0 {
		result.Summary.AverageChainDepth = float64(totalDepth) / float64(len(result.Chains))
	}
	result.Summary.MaxChainDepth = maxDepth
	result.Summary.ChainsWithAdmin = adminCount
}

func generateDOTOutput(chains []IdentityChain) string {
	var sb strings.Builder
	sb.WriteString("digraph IdentityChain {\n")
	sb.WriteString("  rankdir=LR;\n")
	sb.WriteString("  node [shape=box];\n")
	sb.WriteString("\n")

	nodeSet := make(map[string]bool)
	edgeSet := make(map[string]bool)

	for _, chain := range chains {
		workloadID := fmt.Sprintf("w_%s_%s", chain.WorkloadNamespace, chain.WorkloadName)
		if !nodeSet[workloadID] {
			nodeSet[workloadID] = true
			color := "lightblue"
			if chain.RiskLevel == "critical" {
				color = "red"
			} else if chain.RiskLevel == "high" {
				color = "orange"
			}
			sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\\n%s/%s\" style=filled fillcolor=%s];\n",
				workloadID, chain.WorkloadKind, chain.WorkloadNamespace, chain.WorkloadName, color))
		}

		if chain.ServiceAccount != nil {
			saID := fmt.Sprintf("sa_%s_%s", chain.ServiceAccount.Namespace, chain.ServiceAccount.Name)
			if !nodeSet[saID] {
				nodeSet[saID] = true
				sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"SA\\n%s/%s\" style=filled fillcolor=lightyellow];\n",
					saID, chain.ServiceAccount.Namespace, chain.ServiceAccount.Name))
			}
			edgeKey := workloadID + "->" + saID
			if !edgeSet[edgeKey] {
				edgeSet[edgeKey] = true
				sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"uses\"];\n", workloadID, saID))
			}

			for _, role := range chain.K8sRoles {
				roleID := fmt.Sprintf("role_%s_%s", role.Namespace, role.Name)
				if !nodeSet[roleID] {
					nodeSet[roleID] = true
					roleType := "Role"
					if role.IsClusterRole {
						roleType = "ClusterRole"
					}
					sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s\\n%s\" style=filled fillcolor=lightgreen];\n",
						roleID, roleType, role.Name))
				}
				edgeKey := saID + "->" + roleID
				if !edgeSet[edgeKey] {
					edgeSet[edgeKey] = true
					sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"bound via\\n%s\"];\n", saID, roleID, role.ViaBinding))
				}
			}

			for _, cloudRole := range chain.CloudRoles {
				cloudID := fmt.Sprintf("cloud_%s_%s", cloudRole.Provider, cloudRole.RoleName)
				if !nodeSet[cloudID] {
					nodeSet[cloudID] = true
					color := "lightpink"
					if cloudRole.IsAdmin {
						color = "red"
					}
					sb.WriteString(fmt.Sprintf("  \"%s\" [label=\"%s IAM\\n%s\" style=filled fillcolor=%s];\n",
						cloudID, strings.ToUpper(cloudRole.Provider), cloudRole.RoleName, color))
				}
				edgeKey := saID + "->" + cloudID
				if !edgeSet[edgeKey] {
					edgeSet[edgeKey] = true
					sb.WriteString(fmt.Sprintf("  \"%s\" -> \"%s\" [label=\"assumes\" style=dashed color=blue];\n", saID, cloudID))
				}
			}
		}
	}

	sb.WriteString("}\n")
	return sb.String()
}

func generateMermaidOutput(chains []IdentityChain) string {
	var sb strings.Builder
	sb.WriteString("graph LR\n")

	nodeSet := make(map[string]bool)
	edgeSet := make(map[string]bool)

	for i, chain := range chains {
		if i >= 20 {
			break
		}

		workloadID := fmt.Sprintf("W%d", i)
		workloadLabel := fmt.Sprintf("%s/%s", chain.WorkloadNamespace, chain.WorkloadName)
		if !nodeSet[workloadID] {
			nodeSet[workloadID] = true
			sb.WriteString(fmt.Sprintf("    %s[%s]\n", workloadID, workloadLabel))
		}

		if chain.ServiceAccount != nil {
			saID := fmt.Sprintf("SA%d", i)
			saLabel := fmt.Sprintf("%s/%s", chain.ServiceAccount.Namespace, chain.ServiceAccount.Name)
			if !nodeSet[saID] {
				nodeSet[saID] = true
				sb.WriteString(fmt.Sprintf("    %s([%s])\n", saID, saLabel))
			}
			edgeKey := workloadID + "->" + saID
			if !edgeSet[edgeKey] {
				edgeSet[edgeKey] = true
				sb.WriteString(fmt.Sprintf("    %s -->|uses| %s\n", workloadID, saID))
			}

			for j, role := range chain.K8sRoles {
				if j >= 5 {
					break
				}
				roleID := fmt.Sprintf("R%d_%d", i, j)
				if !nodeSet[roleID] {
					nodeSet[roleID] = true
					sb.WriteString(fmt.Sprintf("    %s{%s}\n", roleID, role.Name))
				}
				edgeKey := saID + "->" + roleID
				if !edgeSet[edgeKey] {
					edgeSet[edgeKey] = true
					sb.WriteString(fmt.Sprintf("    %s -->|binds| %s\n", saID, roleID))
				}
			}

			for j, cloudRole := range chain.CloudRoles {
				if j >= 3 {
					break
				}
				cloudID := fmt.Sprintf("C%d_%d", i, j)
				if !nodeSet[cloudID] {
					nodeSet[cloudID] = true
					sb.WriteString(fmt.Sprintf("    %s((%s))\n", cloudID, cloudRole.RoleName))
				}
				edgeKey := saID + "->" + cloudID
				if !edgeSet[edgeKey] {
					edgeSet[edgeKey] = true
					sb.WriteString(fmt.Sprintf("    %s -.->|assumes| %s\n", saID, cloudID))
				}
			}
		}
	}

	return sb.String()
}

func GetIdentityChainForWorkload(g *graph.Graph, workloadRef, namespace string) *IdentityChain {
	result := AnalyzeIdentityChains(g, IdentityChainOptions{
		Namespace:   namespace,
		WorkloadRef: workloadRef,
		MaxDepth:    10,
	})

	if len(result.Chains) > 0 {
		return &result.Chains[0]
	}
	return nil
}
