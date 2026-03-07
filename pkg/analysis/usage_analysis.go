package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type UsageAnalysisOptions struct {
	Namespace      string
	IncludeSystem  bool
	StaleDays      int
	MinPermissions int
}

type UsageAnalysisResult struct {
	UnusedServiceAccounts   []UnusedServiceAccount    `json:"unused_service_accounts"`
	OrphanedIdentities      []OrphanedIdentity        `json:"orphaned_identities"`
	OverProvisionedAccounts []OverProvisionedAccount  `json:"over_provisioned_accounts"`
	StaleIdentities         []StaleIdentity           `json:"stale_identities"`
	RightSizingRecommendations []RightSizingRec       `json:"right_sizing_recommendations"`
	Summary                 UsageAnalysisSummary      `json:"summary"`
	Recommendations         []string                  `json:"recommendations"`
}

type UnusedServiceAccount struct {
	Name            string   `json:"name"`
	Namespace       string   `json:"namespace"`
	HasRoleBindings bool     `json:"has_role_bindings"`
	RoleBindings    []string `json:"role_bindings,omitempty"`
	HasCloudRole    bool     `json:"has_cloud_role"`
	CloudRoleARN    string   `json:"cloud_role_arn,omitempty"`
	CreatedDaysAgo  int      `json:"created_days_ago,omitempty"`
	Reason          string   `json:"reason"`
	RiskLevel       string   `json:"risk_level"`
}

type OrphanedIdentity struct {
	Name            string   `json:"name"`
	Namespace       string   `json:"namespace"`
	Type            string   `json:"type"`
	RoleBindings    []string `json:"role_bindings"`
	EffectiveRoles  []string `json:"effective_roles"`
	OrphanReason    string   `json:"orphan_reason"`
	RiskLevel       string   `json:"risk_level"`
	HasSecretsAccess bool    `json:"has_secrets_access"`
	HasClusterAdmin bool     `json:"has_cluster_admin"`
}

type OverProvisionedAccount struct {
	Name              string             `json:"name"`
	Namespace         string             `json:"namespace"`
	Type              string             `json:"type"`
	GrantedPerms      int                `json:"granted_permissions"`
	UsedPerms         int                `json:"used_permissions"`
	UnusedPerms       int                `json:"unused_permissions"`
	OverProvisionRate float64            `json:"over_provision_rate"`
	UnusedPermissions []UnusedPermission `json:"unused_permissions_detail,omitempty"`
	Roles             []string           `json:"roles"`
	RiskLevel         string             `json:"risk_level"`
}

type UnusedPermission struct {
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
	ViaRole  string   `json:"via_role"`
}

type StaleIdentity struct {
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	Type           string `json:"type"`
	LastUsedDays   int    `json:"last_used_days"`
	HasBindings    bool   `json:"has_bindings"`
	BindingsCount  int    `json:"bindings_count"`
	RiskLevel      string `json:"risk_level"`
	HasPrivileged  bool   `json:"has_privileged"`
}

type RightSizingRec struct {
	Identity         string   `json:"identity"`
	Namespace        string   `json:"namespace"`
	CurrentRoles     []string `json:"current_roles"`
	SuggestedRoles   []string `json:"suggested_roles"`
	RemovablePerms   []string `json:"removable_permissions"`
	ImpactLevel      string   `json:"impact_level"`
	Reason           string   `json:"reason"`
}

type UsageAnalysisSummary struct {
	TotalServiceAccounts    int            `json:"total_service_accounts"`
	UnusedCount             int            `json:"unused_count"`
	OrphanedCount           int            `json:"orphaned_count"`
	OverProvisionedCount    int            `json:"over_provisioned_count"`
	StaleCount              int            `json:"stale_count"`
	TotalRightSizingRecs    int            `json:"total_right_sizing_recs"`
	ByNamespace             map[string]int `json:"by_namespace"`
	HighRiskUnused          int            `json:"high_risk_unused"`
	WithUnusedCloudPerms    int            `json:"with_unused_cloud_perms"`
	AvgOverProvisionRate    float64        `json:"avg_over_provision_rate"`
}

// isSystemNamespace returns true if the namespace is a Kubernetes system namespace.
// It mirrors collector.IsSystemNamespace but avoids the import cycle by replicating
// the lightweight logic here. Extended patterns cover common distro-specific namespaces.
func isSystemNamespace(ns string) bool {
	systemNamespaces := map[string]bool{
		"kube-system":     true,
		"kube-public":     true,
		"kube-node-lease": true,
	}
	if systemNamespaces[ns] {
		return true
	}
	// Cover common distro / add-on namespaces without pulling in the collector package.
	prefixes := []string{
		"openshift-",
		"cattle-",
		"fleet-",
		"rancher-",
	}
	for _, p := range prefixes {
		if strings.HasPrefix(ns, p) {
			return true
		}
	}
	return false
}

// findWorkloadsUsingSA returns all workload nodes that have an EdgeUses edge pointing
// to the given service-account node. The graph already maintains a saToWorkloads index
// (accessed via GetWorkloadsUsingSA), so we delegate to it for efficiency.
func findWorkloadsUsingSA(g *graph.Graph, sa *graph.Node) []*graph.Node {
	return g.GetWorkloadsUsingSA(sa.ID)
}

func AnalyzeUsage(g *graph.Graph, opts UsageAnalysisOptions) *UsageAnalysisResult {
	result := &UsageAnalysisResult{
		UnusedServiceAccounts:      []UnusedServiceAccount{},
		OrphanedIdentities:         []OrphanedIdentity{},
		OverProvisionedAccounts:    []OverProvisionedAccount{},
		StaleIdentities:            []StaleIdentity{},
		RightSizingRecommendations: []RightSizingRec{},
		Recommendations:            []string{},
		Summary: UsageAnalysisSummary{
			ByNamespace: make(map[string]int),
		},
	}

	if opts.StaleDays == 0 {
		opts.StaleDays = 30
	}

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	result.Summary.TotalServiceAccounts = len(serviceAccounts)

	for _, sa := range serviceAccounts {
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}

		if !opts.IncludeSystem && isSystemNamespace(sa.Namespace) {
			continue
		}

		result.Summary.ByNamespace[sa.Namespace]++

		workloadsUsing := findWorkloadsUsingSA(g, sa)
		hasWorkloads := len(workloadsUsing) > 0

		roleBindings := findRoleBindingsForSA(g, sa)
		hasBindings := len(roleBindings) > 0

		effectiveRoles := getEffectiveRolesForSA(g, sa)
		hasClusterAdmin, hasSecretsAccess := analyzeRolePermissions(g, effectiveRoles)

		if !hasWorkloads {
			unused := UnusedServiceAccount{
				Name:            sa.Name,
				Namespace:       sa.Namespace,
				HasRoleBindings: hasBindings,
				HasCloudRole:    sa.HasCloudIdentity(),
				Reason:          "No workloads using this service account",
			}

			if hasBindings {
				for _, rb := range roleBindings {
					unused.RoleBindings = append(unused.RoleBindings, rb.Name)
				}
			}
			if sa.Metadata.CloudRoleARN != "" {
				unused.CloudRoleARN = sa.Metadata.CloudRoleARN
			}

			if hasClusterAdmin || sa.HasCloudIdentity() {
				unused.RiskLevel = "critical"
				result.Summary.HighRiskUnused++
			} else if hasSecretsAccess || hasBindings {
				unused.RiskLevel = "high"
				result.Summary.HighRiskUnused++
			} else {
				unused.RiskLevel = "medium"
			}

			result.UnusedServiceAccounts = append(result.UnusedServiceAccounts, unused)
			result.Summary.UnusedCount++
		}

		if hasBindings && !hasWorkloads {
			orphaned := OrphanedIdentity{
				Name:             sa.Name,
				Namespace:        sa.Namespace,
				Type:             "ServiceAccount",
				RoleBindings:     []string{},
				EffectiveRoles:   effectiveRoles,
				OrphanReason:     "Has role bindings but no workloads attached",
				HasSecretsAccess: hasSecretsAccess,
				HasClusterAdmin:  hasClusterAdmin,
			}

			for _, rb := range roleBindings {
				orphaned.RoleBindings = append(orphaned.RoleBindings, rb.Name)
			}

			if hasClusterAdmin {
				orphaned.RiskLevel = "critical"
			} else if hasSecretsAccess {
				orphaned.RiskLevel = "high"
			} else {
				orphaned.RiskLevel = "medium"
			}

			result.OrphanedIdentities = append(result.OrphanedIdentities, orphaned)
			result.Summary.OrphanedCount++
		}

		if hasBindings && len(effectiveRoles) > 0 {
			overprov := analyzeOverProvisioning(g, sa, effectiveRoles)
			if overprov != nil && overprov.OverProvisionRate > 0.5 {
				result.OverProvisionedAccounts = append(result.OverProvisionedAccounts, *overprov)
				result.Summary.OverProvisionedCount++
			}
		}
	}

	users := g.GetNodesByType(graph.NodeUser)
	for _, user := range users {
		if opts.Namespace != "" && user.Namespace != opts.Namespace && user.Namespace != "" {
			continue
		}

		roleBindings := findRoleBindingsForUser(g, user)
		if len(roleBindings) > 0 {
			hasActivity := checkUserActivity(user)
			if !hasActivity {
				orphaned := OrphanedIdentity{
					Name:         user.Name,
					Namespace:    user.Namespace,
					Type:         "User",
					RoleBindings: []string{},
					OrphanReason: "User identity with no recent activity",
					RiskLevel:    "medium",
				}
				for _, rb := range roleBindings {
					orphaned.RoleBindings = append(orphaned.RoleBindings, rb.Name)
				}
				result.OrphanedIdentities = append(result.OrphanedIdentities, orphaned)
				result.Summary.OrphanedCount++
			}
		}
	}

	result.RightSizingRecommendations = generateRightSizingRecommendations(result)
	result.Summary.TotalRightSizingRecs = len(result.RightSizingRecommendations)

	calculateOverprovisioningStats(result)
	generateUsageRecommendations(result)

	sort.Slice(result.UnusedServiceAccounts, func(i, j int) bool {
		riskOrder := map[string]int{"critical": 4, "high": 3, "medium": 2, "low": 1}
		return riskOrder[result.UnusedServiceAccounts[i].RiskLevel] > riskOrder[result.UnusedServiceAccounts[j].RiskLevel]
	})

	return result
}

func findRoleBindingsForSA(g *graph.Graph, sa *graph.Node) []*graph.Node {
	var bindings []*graph.Node

	inEdges := g.GetInEdges(sa.ID)
	for _, edge := range inEdges {
		if edge.Type == graph.EdgeBinds {
			binding := g.GetNode(edge.From)
			if binding != nil {
				bindings = append(bindings, binding)
			}
		}
	}

	return bindings
}

func findRoleBindingsForUser(g *graph.Graph, user *graph.Node) []*graph.Node {
	var bindings []*graph.Node

	inEdges := g.GetInEdges(user.ID)
	for _, edge := range inEdges {
		if edge.Type == graph.EdgeBinds {
			binding := g.GetNode(edge.From)
			if binding != nil {
				bindings = append(bindings, binding)
			}
		}
	}

	return bindings
}

func getEffectiveRolesForSA(g *graph.Graph, sa *graph.Node) []string {
	var roles []string
	roleSet := make(map[string]bool)

	bindings := findRoleBindingsForSA(g, sa)
	for _, binding := range bindings {
		outEdges := g.GetOutEdges(binding.ID)
		for _, edge := range outEdges {
			if edge.Type == graph.EdgeGrants {
				roleNode := g.GetNode(edge.To)
				if roleNode != nil && roleNode.Type == graph.NodeRole {
					if !roleSet[roleNode.Name] {
						roleSet[roleNode.Name] = true
						roles = append(roles, roleNode.Name)
					}
				}
			}
		}
	}

	return roles
}

func analyzeRolePermissions(g *graph.Graph, roleNames []string) (hasClusterAdmin, hasSecretsAccess bool) {
	for _, roleName := range roleNames {
		if roleName == "cluster-admin" {
			return true, true
		}

		roleID := graph.GenerateNodeID(graph.NodeRole, "", roleName)
		roleNode := g.GetNode(roleID)
		if roleNode == nil {
			continue
		}

		for _, rule := range roleNode.Metadata.Rules {
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
				if res == "secrets" {
					for _, verb := range rule.Verbs {
						if verb == "get" || verb == "list" || verb == "watch" || verb == "*" {
							hasSecretsAccess = true
						}
					}
				}
			}

			if hasWildcardVerb && hasWildcardResource && roleNode.Metadata.IsClusterRole {
				hasClusterAdmin = true
			}
		}
	}

	return
}

func analyzeOverProvisioning(g *graph.Graph, sa *graph.Node, roles []string) *OverProvisionedAccount {
	account := &OverProvisionedAccount{
		Name:              sa.Name,
		Namespace:         sa.Namespace,
		Type:              "ServiceAccount",
		Roles:             roles,
		UnusedPermissions: []UnusedPermission{},
	}

	grantedCount := 0
	for _, roleName := range roles {
		roleID := graph.GenerateNodeID(graph.NodeRole, "", roleName)
		roleNode := g.GetNode(roleID)
		if roleNode == nil {
			roleID = graph.GenerateNodeID(graph.NodeRole, sa.Namespace, roleName)
			roleNode = g.GetNode(roleID)
		}
		if roleNode == nil {
			continue
		}

		for _, rule := range roleNode.Metadata.Rules {
			permCount := len(rule.Resources) * len(rule.Verbs)
			grantedCount += permCount

			for _, res := range rule.Resources {
				unused := UnusedPermission{
					Resource: res,
					Verbs:    rule.Verbs,
					ViaRole:  roleName,
				}
				account.UnusedPermissions = append(account.UnusedPermissions, unused)
			}
		}
	}

	account.GrantedPerms = grantedCount
	account.UsedPerms = estimateUsedPermissions(sa)
	account.UnusedPerms = account.GrantedPerms - account.UsedPerms

	if account.GrantedPerms > 0 {
		account.OverProvisionRate = float64(account.UnusedPerms) / float64(account.GrantedPerms)
	}

	if account.OverProvisionRate > 0.9 {
		account.RiskLevel = "high"
	} else if account.OverProvisionRate > 0.7 {
		account.RiskLevel = "medium"
	} else {
		account.RiskLevel = "low"
	}

	return account
}

func estimateUsedPermissions(sa *graph.Node) int {
	baseUsed := 3

	if sa.Metadata.AutomountToken {
		baseUsed += 2
	}

	return baseUsed
}

func checkUserActivity(user *graph.Node) bool {
	if user.Annotations != nil {
		if _, ok := user.Annotations["last-activity"]; ok {
			return true
		}
	}
	return false
}

func generateRightSizingRecommendations(result *UsageAnalysisResult) []RightSizingRec {
	var recs []RightSizingRec

	for _, unused := range result.UnusedServiceAccounts {
		if unused.HasRoleBindings {
			rec := RightSizingRec{
				Identity:       unused.Name,
				Namespace:      unused.Namespace,
				CurrentRoles:   unused.RoleBindings,
				SuggestedRoles: []string{},
				RemovablePerms: unused.RoleBindings,
				ImpactLevel:    "none",
				Reason:         "Service account has no workloads - remove role bindings",
			}
			recs = append(recs, rec)
		}
	}

	for _, orphaned := range result.OrphanedIdentities {
		if orphaned.Type == "ServiceAccount" && len(orphaned.RoleBindings) > 0 {
			rec := RightSizingRec{
				Identity:       orphaned.Name,
				Namespace:      orphaned.Namespace,
				CurrentRoles:   orphaned.RoleBindings,
				SuggestedRoles: []string{},
				RemovablePerms: orphaned.RoleBindings,
				Reason:         fmt.Sprintf("Orphaned: %s", orphaned.OrphanReason),
			}
			if orphaned.HasClusterAdmin {
				rec.ImpactLevel = "critical"
			} else if orphaned.HasSecretsAccess {
				rec.ImpactLevel = "high"
			} else {
				rec.ImpactLevel = "medium"
			}
			recs = append(recs, rec)
		}
	}

	for _, overprov := range result.OverProvisionedAccounts {
		if overprov.OverProvisionRate > 0.7 {
			rec := RightSizingRec{
				Identity:       overprov.Name,
				Namespace:      overprov.Namespace,
				CurrentRoles:   overprov.Roles,
				SuggestedRoles: suggestMinimalRoles(overprov),
				RemovablePerms: []string{},
				ImpactLevel:    overprov.RiskLevel,
				Reason:         fmt.Sprintf("%.0f%% of permissions unused", overprov.OverProvisionRate*100),
			}
			for _, unused := range overprov.UnusedPermissions {
				rec.RemovablePerms = append(rec.RemovablePerms, fmt.Sprintf("%s:%s", unused.Resource, unused.Verbs[0]))
			}
			recs = append(recs, rec)
		}
	}

	return recs
}

func suggestMinimalRoles(account OverProvisionedAccount) []string {
	hasClusterAdmin := false
	for _, role := range account.Roles {
		if role == "cluster-admin" {
			hasClusterAdmin = true
		}
	}

	if hasClusterAdmin {
		return []string{"view"}
	}

	return []string{"view"}
}

func calculateOverprovisioningStats(result *UsageAnalysisResult) {
	if len(result.OverProvisionedAccounts) == 0 {
		return
	}

	totalRate := 0.0
	for _, acc := range result.OverProvisionedAccounts {
		totalRate += acc.OverProvisionRate
	}

	result.Summary.AvgOverProvisionRate = totalRate / float64(len(result.OverProvisionedAccounts))
}

func generateUsageRecommendations(result *UsageAnalysisResult) {
	if result.Summary.UnusedCount > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Remove or audit %d unused service accounts", result.Summary.UnusedCount))
	}

	if result.Summary.HighRiskUnused > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("URGENT: %d unused accounts have cluster-admin or cloud access", result.Summary.HighRiskUnused))
	}

	if result.Summary.OrphanedCount > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Clean up %d orphaned identities with unused role bindings", result.Summary.OrphanedCount))
	}

	if result.Summary.OverProvisionedCount > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Right-size %d over-provisioned accounts (avg %.0f%% unused permissions)",
				result.Summary.OverProvisionedCount, result.Summary.AvgOverProvisionRate*100))
	}

	if result.Summary.TotalServiceAccounts > 50 && result.Summary.UnusedCount > result.Summary.TotalServiceAccounts/4 {
		result.Recommendations = append(result.Recommendations,
			"Consider implementing service account lifecycle management")
	}
}

func GetUnusedServiceAccounts(g *graph.Graph, opts UsageAnalysisOptions) []UnusedServiceAccount {
	result := AnalyzeUsage(g, opts)
	return result.UnusedServiceAccounts
}
