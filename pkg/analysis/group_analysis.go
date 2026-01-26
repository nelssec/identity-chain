package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type GroupAnalysisOptions struct {
	Namespace     string
	IncludeSystem bool
}

type GroupAnalysisResult struct {
	Groups              []GroupInfo            `json:"groups"`
	HighRiskGroups      []GroupInfo            `json:"high_risk_groups"`
	OIDCGroupMappings   []OIDCGroupMapping     `json:"oidc_group_mappings"`
	NestedPermissions   []NestedPermissionPath `json:"nested_permissions"`
	PrivilegeEscalation []GroupPrivEscPath     `json:"privilege_escalation_paths"`
	Summary             GroupAnalysisSummary   `json:"summary"`
	Recommendations     []string               `json:"recommendations"`
}

type GroupInfo struct {
	Name            string             `json:"name"`
	Type            string             `json:"type"`
	MemberCount     int                `json:"member_count"`
	Members         []GroupMember      `json:"members,omitempty"`
	RoleBindings    []GroupRoleBinding `json:"role_bindings"`
	EffectiveRoles  []EffectiveRole    `json:"effective_roles"`
	RiskScore       int                `json:"risk_score"`
	RiskLevel       string             `json:"risk_level"`
	RiskFactors     []string           `json:"risk_factors,omitempty"`
	HasClusterAdmin bool               `json:"has_cluster_admin"`
	HasSecretsAccess bool              `json:"has_secrets_access"`
	Namespaces      []string           `json:"namespaces,omitempty"`
}

type GroupMember struct {
	Name      string `json:"name"`
	Type      string `json:"type"`
	Namespace string `json:"namespace,omitempty"`
}

type GroupRoleBinding struct {
	BindingName     string `json:"binding_name"`
	BindingType     string `json:"binding_type"`
	RoleName        string `json:"role_name"`
	RoleType        string `json:"role_type"`
	Namespace       string `json:"namespace,omitempty"`
}

type EffectiveRole struct {
	RoleName      string       `json:"role_name"`
	IsClusterRole bool         `json:"is_cluster_role"`
	Namespace     string       `json:"namespace,omitempty"`
	Rules         []graph.Rule `json:"rules,omitempty"`
	ViaBinding    string       `json:"via_binding"`
}

type OIDCGroupMapping struct {
	OIDCProvider   string   `json:"oidc_provider"`
	OIDCGroup      string   `json:"oidc_group"`
	K8sGroup       string   `json:"k8s_group"`
	ClaimPath      string   `json:"claim_path,omitempty"`
	EffectiveRoles []string `json:"effective_roles"`
	RiskLevel      string   `json:"risk_level"`
}

type NestedPermissionPath struct {
	StartGroup        string   `json:"start_group"`
	Path              []string `json:"path"`
	EndPermission     string   `json:"end_permission"`
	EffectiveVerbs    []string `json:"effective_verbs"`
	EffectiveResource string   `json:"effective_resource"`
	Depth             int      `json:"depth"`
	RiskLevel         string   `json:"risk_level"`
}

type GroupPrivEscPath struct {
	Group           string   `json:"group"`
	EscalationPath  []string `json:"escalation_path"`
	TargetRole      string   `json:"target_role"`
	Technique       string   `json:"technique"`
	Severity        string   `json:"severity"`
	Description     string   `json:"description"`
}

type GroupAnalysisSummary struct {
	TotalGroups          int            `json:"total_groups"`
	HighRiskGroups       int            `json:"high_risk_groups"`
	GroupsWithAdmin      int            `json:"groups_with_admin"`
	GroupsWithSecrets    int            `json:"groups_with_secrets"`
	OIDCMappings         int            `json:"oidc_mappings"`
	PrivEscPaths         int            `json:"priv_esc_paths"`
	TotalRoleBindings    int            `json:"total_role_bindings"`
	ByGroupType          map[string]int `json:"by_group_type"`
	ByRiskLevel          map[string]int `json:"by_risk_level"`
}

func AnalyzeGroups(g *graph.Graph, opts GroupAnalysisOptions) *GroupAnalysisResult {
	result := &GroupAnalysisResult{
		Groups:              []GroupInfo{},
		HighRiskGroups:      []GroupInfo{},
		OIDCGroupMappings:   []OIDCGroupMapping{},
		NestedPermissions:   []NestedPermissionPath{},
		PrivilegeEscalation: []GroupPrivEscPath{},
		Recommendations:     []string{},
		Summary: GroupAnalysisSummary{
			ByGroupType: make(map[string]int),
			ByRiskLevel: make(map[string]int),
		},
	}

	groupNodes := g.GetNodesByType(graph.NodeGroup)

	for _, groupNode := range groupNodes {
		groupInfo := analyzeGroup(g, groupNode, opts)
		result.Groups = append(result.Groups, groupInfo)

		result.Summary.ByGroupType[groupInfo.Type]++
		result.Summary.ByRiskLevel[groupInfo.RiskLevel]++
		result.Summary.TotalRoleBindings += len(groupInfo.RoleBindings)

		if groupInfo.RiskScore >= 70 {
			result.HighRiskGroups = append(result.HighRiskGroups, groupInfo)
			result.Summary.HighRiskGroups++
		}
		if groupInfo.HasClusterAdmin {
			result.Summary.GroupsWithAdmin++
		}
		if groupInfo.HasSecretsAccess {
			result.Summary.GroupsWithSecrets++
		}
	}

	detectBuiltinGroups(g, result, opts)

	result.OIDCGroupMappings = detectOIDCMappings(g, result.Groups)
	result.Summary.OIDCMappings = len(result.OIDCGroupMappings)

	result.PrivilegeEscalation = detectGroupPrivilegeEscalation(g, result.Groups)
	result.Summary.PrivEscPaths = len(result.PrivilegeEscalation)

	result.NestedPermissions = analyzeNestedPermissions(g, result.Groups)

	result.Summary.TotalGroups = len(result.Groups)

	sort.Slice(result.Groups, func(i, j int) bool {
		return result.Groups[i].RiskScore > result.Groups[j].RiskScore
	})

	generateGroupRecommendations(result)

	return result
}

func analyzeGroup(g *graph.Graph, groupNode *graph.Node, opts GroupAnalysisOptions) GroupInfo {
	group := GroupInfo{
		Name:           groupNode.Name,
		Type:           detectGroupType(groupNode),
		Members:        []GroupMember{},
		RoleBindings:   []GroupRoleBinding{},
		EffectiveRoles: []EffectiveRole{},
		RiskFactors:    []string{},
		Namespaces:     []string{},
	}

	inEdges := g.GetInEdges(groupNode.ID)
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
						binding := GroupRoleBinding{
							BindingName: bindingNode.Name,
							BindingType: detectBindingType(bindingNode),
							RoleName:    roleNode.Name,
							RoleType:    detectRoleType(roleNode),
							Namespace:   bindingNode.Namespace,
						}
						group.RoleBindings = append(group.RoleBindings, binding)

						effRole := EffectiveRole{
							RoleName:      roleNode.Name,
							IsClusterRole: roleNode.Metadata.IsClusterRole,
							Namespace:     roleNode.Namespace,
							Rules:         roleNode.Metadata.Rules,
							ViaBinding:    bindingNode.Name,
						}
						group.EffectiveRoles = append(group.EffectiveRoles, effRole)

						if bindingNode.Namespace != "" && !containsString(group.Namespaces, bindingNode.Namespace) {
							group.Namespaces = append(group.Namespaces, bindingNode.Namespace)
						}
					}
				}
			}
		}
	}

	for _, role := range group.EffectiveRoles {
		if isClusterAdminRole(role) {
			group.HasClusterAdmin = true
			group.RiskFactors = append(group.RiskFactors, "Has cluster-admin privileges")
		}
		if hasSecretsAccess(role) {
			group.HasSecretsAccess = true
			group.RiskFactors = append(group.RiskFactors, "Can access secrets")
		}
	}

	group.RiskScore = calculateGroupRiskScore(&group)
	group.RiskLevel = getRiskLevel(group.RiskScore)

	return group
}

func detectGroupType(node *graph.Node) string {
	name := strings.ToLower(node.Name)

	if strings.HasPrefix(name, "system:") {
		return "system"
	}
	if strings.Contains(name, "oidc:") || strings.Contains(name, "azure-ad:") ||
	   strings.Contains(name, "google:") || strings.Contains(name, "okta:") {
		return "oidc"
	}
	if strings.Contains(name, "ldap:") || strings.Contains(name, "ad:") {
		return "ldap"
	}
	if strings.HasPrefix(name, "aws-") || strings.HasPrefix(name, "eks-") {
		return "aws"
	}
	if strings.HasPrefix(name, "gke-") || strings.HasPrefix(name, "gcp-") {
		return "gcp"
	}
	if strings.HasPrefix(name, "aks-") || strings.HasPrefix(name, "azure-") {
		return "azure"
	}

	return "custom"
}

func detectBindingType(node *graph.Node) string {
	if node.Namespace == "" {
		return "ClusterRoleBinding"
	}
	return "RoleBinding"
}

func detectRoleType(node *graph.Node) string {
	if node.Metadata.IsClusterRole {
		return "ClusterRole"
	}
	return "Role"
}

func isClusterAdminRole(role EffectiveRole) bool {
	if role.RoleName == "cluster-admin" {
		return true
	}

	for _, rule := range role.Rules {
		hasWildcardVerb := false
		hasWildcardResource := false
		for _, verb := range rule.Verbs {
			if verb == "*" {
				hasWildcardVerb = true
			}
		}
		for _, res := range rule.Resources {
			if res == "*" {
				hasWildcardResource = true
			}
		}
		if hasWildcardVerb && hasWildcardResource && role.IsClusterRole {
			return true
		}
	}
	return false
}

func hasSecretsAccess(role EffectiveRole) bool {
	for _, rule := range role.Rules {
		for _, res := range rule.Resources {
			if res == "secrets" || res == "*" {
				for _, verb := range rule.Verbs {
					if verb == "get" || verb == "list" || verb == "watch" || verb == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func calculateGroupRiskScore(group *GroupInfo) int {
	score := 0

	if group.HasClusterAdmin {
		score += 50
	}
	if group.HasSecretsAccess {
		score += 20
	}

	score += len(group.RoleBindings) * 5

	if len(group.Namespaces) > 5 {
		score += 15
	}

	if group.Type == "oidc" || group.Type == "ldap" {
		score += 10
	}

	for _, role := range group.EffectiveRoles {
		if role.IsClusterRole {
			score += 10
		}
		for _, rule := range role.Rules {
			for _, verb := range rule.Verbs {
				if verb == "*" {
					score += 5
				}
				if verb == "escalate" || verb == "bind" || verb == "impersonate" {
					score += 15
				}
			}
		}
	}

	if score > 100 {
		score = 100
	}

	return score
}

func detectBuiltinGroups(g *graph.Graph, result *GroupAnalysisResult, opts GroupAnalysisOptions) {
	builtinGroups := []string{
		"system:authenticated",
		"system:unauthenticated",
		"system:masters",
		"system:nodes",
		"system:serviceaccounts",
	}

	for _, groupName := range builtinGroups {
		found := false
		for _, existing := range result.Groups {
			if existing.Name == groupName {
				found = true
				break
			}
		}

		if !found {
			groupInfo := GroupInfo{
				Name:           groupName,
				Type:           "system",
				Members:        []GroupMember{},
				RoleBindings:   []GroupRoleBinding{},
				EffectiveRoles: []EffectiveRole{},
				RiskFactors:    []string{},
			}

			groupID := graph.GenerateNodeID(graph.NodeGroup, "", groupName)
			groupNode := g.GetNode(groupID)
			if groupNode != nil {
				groupInfo = analyzeGroup(g, groupNode, opts)
			} else {
				scanRoleBindingsForGroup(g, groupName, &groupInfo)
			}

			if groupName == "system:masters" {
				groupInfo.HasClusterAdmin = true
				groupInfo.RiskScore = 100
				groupInfo.RiskLevel = "critical"
				groupInfo.RiskFactors = append(groupInfo.RiskFactors, "Built-in cluster admin group")
			}

			if len(groupInfo.RoleBindings) > 0 || groupName == "system:masters" {
				result.Groups = append(result.Groups, groupInfo)
				result.Summary.ByGroupType[groupInfo.Type]++
				result.Summary.ByRiskLevel[groupInfo.RiskLevel]++
			}
		}
	}
}

func scanRoleBindingsForGroup(g *graph.Graph, groupName string, groupInfo *GroupInfo) {
	for _, edge := range g.AllEdges() {
		if edge.Type != graph.EdgeBinds {
			continue
		}

		bindingNode := g.GetNode(edge.From)
		if bindingNode == nil {
			continue
		}

		targetNode := g.GetNode(edge.To)
		if targetNode == nil || targetNode.Type != graph.NodeGroup {
			continue
		}
		if targetNode.Name != groupName {
			continue
		}

		bindingEdges := g.GetOutEdges(bindingNode.ID)
		for _, be := range bindingEdges {
			if be.Type == graph.EdgeGrants {
				roleNode := g.GetNode(be.To)
				if roleNode != nil && roleNode.Type == graph.NodeRole {
					binding := GroupRoleBinding{
						BindingName: bindingNode.Name,
						BindingType: detectBindingType(bindingNode),
						RoleName:    roleNode.Name,
						RoleType:    detectRoleType(roleNode),
						Namespace:   bindingNode.Namespace,
					}
					groupInfo.RoleBindings = append(groupInfo.RoleBindings, binding)

					effRole := EffectiveRole{
						RoleName:      roleNode.Name,
						IsClusterRole: roleNode.Metadata.IsClusterRole,
						Namespace:     roleNode.Namespace,
						Rules:         roleNode.Metadata.Rules,
						ViaBinding:    bindingNode.Name,
					}
					groupInfo.EffectiveRoles = append(groupInfo.EffectiveRoles, effRole)
				}
			}
		}
	}

	for _, role := range groupInfo.EffectiveRoles {
		if isClusterAdminRole(role) {
			groupInfo.HasClusterAdmin = true
		}
		if hasSecretsAccess(role) {
			groupInfo.HasSecretsAccess = true
		}
	}

	groupInfo.RiskScore = calculateGroupRiskScore(groupInfo)
	groupInfo.RiskLevel = getRiskLevel(groupInfo.RiskScore)
}

func detectOIDCMappings(g *graph.Graph, groups []GroupInfo) []OIDCGroupMapping {
	var mappings []OIDCGroupMapping

	for _, group := range groups {
		if group.Type != "oidc" {
			continue
		}

		mapping := OIDCGroupMapping{
			K8sGroup:       group.Name,
			EffectiveRoles: []string{},
		}

		parts := strings.SplitN(group.Name, ":", 2)
		if len(parts) >= 2 {
			mapping.OIDCProvider = parts[0]
			mapping.OIDCGroup = parts[1]
		} else {
			mapping.OIDCGroup = group.Name
		}

		for _, role := range group.EffectiveRoles {
			mapping.EffectiveRoles = append(mapping.EffectiveRoles, role.RoleName)
		}

		mapping.RiskLevel = group.RiskLevel

		mappings = append(mappings, mapping)
	}

	return mappings
}

func detectGroupPrivilegeEscalation(g *graph.Graph, groups []GroupInfo) []GroupPrivEscPath {
	var paths []GroupPrivEscPath

	for _, group := range groups {
		for _, role := range group.EffectiveRoles {
			for _, rule := range role.Rules {
				for _, verb := range rule.Verbs {
					if verb == "escalate" {
						paths = append(paths, GroupPrivEscPath{
							Group:          group.Name,
							EscalationPath: []string{group.Name, role.ViaBinding, role.RoleName},
							TargetRole:     "any role",
							Technique:      "RBAC Escalate verb",
							Severity:       "critical",
							Description:    fmt.Sprintf("Group %s can escalate privileges via the escalate verb", group.Name),
						})
					}
					if verb == "bind" {
						paths = append(paths, GroupPrivEscPath{
							Group:          group.Name,
							EscalationPath: []string{group.Name, role.ViaBinding, role.RoleName},
							TargetRole:     "any role",
							Technique:      "RBAC Bind verb",
							Severity:       "critical",
							Description:    fmt.Sprintf("Group %s can bind arbitrary roles", group.Name),
						})
					}
					if verb == "impersonate" {
						paths = append(paths, GroupPrivEscPath{
							Group:          group.Name,
							EscalationPath: []string{group.Name, role.ViaBinding, role.RoleName},
							TargetRole:     "impersonated identity",
							Technique:      "User impersonation",
							Severity:       "high",
							Description:    fmt.Sprintf("Group %s can impersonate other identities", group.Name),
						})
					}
				}

				for _, res := range rule.Resources {
					if res == "rolebindings" || res == "clusterrolebindings" {
						hasCreate := false
						for _, v := range rule.Verbs {
							if v == "create" || v == "*" {
								hasCreate = true
								break
							}
						}
						if hasCreate {
							paths = append(paths, GroupPrivEscPath{
								Group:          group.Name,
								EscalationPath: []string{group.Name, role.ViaBinding, role.RoleName},
								TargetRole:     "any accessible role",
								Technique:      "Role binding creation",
								Severity:       "high",
								Description:    fmt.Sprintf("Group %s can create role bindings to grant itself more permissions", group.Name),
							})
						}
					}

					if res == "secrets" {
						hasRead := false
						for _, v := range rule.Verbs {
							if v == "get" || v == "list" || v == "*" {
								hasRead = true
								break
							}
						}
						if hasRead && role.IsClusterRole {
							paths = append(paths, GroupPrivEscPath{
								Group:          group.Name,
								EscalationPath: []string{group.Name, role.ViaBinding, role.RoleName, "secrets"},
								TargetRole:     "service account tokens",
								Technique:      "Service account token theft",
								Severity:       "high",
								Description:    fmt.Sprintf("Group %s can read secrets including SA tokens", group.Name),
							})
						}
					}
				}
			}
		}
	}

	return paths
}

func analyzeNestedPermissions(g *graph.Graph, groups []GroupInfo) []NestedPermissionPath {
	var paths []NestedPermissionPath

	for _, group := range groups {
		for _, role := range group.EffectiveRoles {
			for _, rule := range role.Rules {
				for _, res := range rule.Resources {
					path := NestedPermissionPath{
						StartGroup:        group.Name,
						Path:              []string{group.Name, role.ViaBinding, role.RoleName},
						EndPermission:     fmt.Sprintf("%s on %s", strings.Join(rule.Verbs, ","), res),
						EffectiveVerbs:    rule.Verbs,
						EffectiveResource: res,
						Depth:             3,
					}

					if containsString(rule.Verbs, "*") || containsString(rule.Resources, "*") {
						path.RiskLevel = "high"
					} else if res == "secrets" || res == "pods/exec" || res == "pods/attach" {
						path.RiskLevel = "high"
					} else if containsString(rule.Verbs, "create") || containsString(rule.Verbs, "delete") {
						path.RiskLevel = "medium"
					} else {
						path.RiskLevel = "low"
					}

					paths = append(paths, path)
				}
			}
		}
	}

	sort.Slice(paths, func(i, j int) bool {
		riskOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
		return riskOrder[paths[i].RiskLevel] > riskOrder[paths[j].RiskLevel]
	})

	if len(paths) > 50 {
		paths = paths[:50]
	}

	return paths
}

func generateGroupRecommendations(result *GroupAnalysisResult) {
	if result.Summary.GroupsWithAdmin > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Review %d groups with cluster-admin privileges - minimize admin access", result.Summary.GroupsWithAdmin))
	}

	if result.Summary.PrivEscPaths > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Address %d privilege escalation paths through groups", result.Summary.PrivEscPaths))
	}

	systemAuthCount := 0
	for _, group := range result.Groups {
		if group.Name == "system:authenticated" && len(group.RoleBindings) > 1 {
			systemAuthCount = len(group.RoleBindings)
		}
	}
	if systemAuthCount > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("system:authenticated has %d bindings - review for excessive access", systemAuthCount))
	}

	for _, mapping := range result.OIDCGroupMappings {
		if mapping.RiskLevel == "high" || mapping.RiskLevel == "critical" {
			result.Recommendations = append(result.Recommendations,
				fmt.Sprintf("OIDC group %s has %s risk - verify IDP group membership", mapping.OIDCGroup, mapping.RiskLevel))
		}
	}

	if result.Summary.GroupsWithSecrets > 3 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("%d groups can access secrets - consolidate secret access", result.Summary.GroupsWithSecrets))
	}
}

