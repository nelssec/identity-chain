package analysis

import (
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/collector"
	"github.com/nelssec/identity-chain/pkg/graph"
)

// RBACFinding represents a security finding in RBAC configuration
type RBACFinding struct {
	CheckID     string
	Category    FindingCategory
	Severity    graph.Severity
	Title       string
	Description string
	Affected    []AffectedResource
	Remediation string
	References  []string
}

// AffectedResource represents a resource affected by a finding
type AffectedResource struct {
	Kind      string
	Namespace string
	Name      string
	Details   string
}

// FindingCategory categorizes the type of security finding
type FindingCategory string

const (
	CategoryPrivilegeEscalation FindingCategory = "privilege_escalation"
	CategoryOverPermissive      FindingCategory = "over_permissive"
	CategoryDefaultConfig       FindingCategory = "default_config"
	CategorySecretAccess        FindingCategory = "secret_access"
	CategoryClusterScope        FindingCategory = "cluster_scope"
	CategoryUnusedAccess        FindingCategory = "unused_access"
	CategoryCrossNamespace      FindingCategory = "cross_namespace"
)

// RBACAuditResult holds all findings from RBAC audit
type RBACAuditResult struct {
	Findings      []RBACFinding
	Summary       AuditSummary
	ChecksRun     []string
	TotalFindings int
}

// AuditSummary provides summary statistics
type AuditSummary struct {
	Critical         int
	High             int
	Medium           int
	Low              int
	ByCategory       map[FindingCategory]int
	TopAffectedSAs   []string
	TopAffectedRoles []string
}

// RBACAuditOptions configures the audit behavior
type RBACAuditOptions struct {
	IncludeSystem  bool
	ChecksToRun    []string // Empty means all checks
	SkipChecks     []string
	Namespace      string // Empty means all namespaces
}

// AuditCheck represents a single security check
type AuditCheck struct {
	ID          string
	Name        string
	Description string
	Category    FindingCategory
	Check       func(g *graph.Graph, opts RBACAuditOptions) []RBACFinding
}

// AllChecks contains all available security checks
var AllChecks = []AuditCheck{
	{
		ID:          "RBAC001",
		Name:        "Default ServiceAccount Usage",
		Description: "Workloads using the default service account may inherit unexpected permissions",
		Category:    CategoryDefaultConfig,
		Check:       checkDefaultSAUsage,
	},
	{
		ID:          "RBAC002",
		Name:        "Automounted SA Tokens",
		Description: "Workloads with automounted tokens that don't need Kubernetes API access",
		Category:    CategoryDefaultConfig,
		Check:       checkAutomountTokens,
	},
	{
		ID:          "RBAC003",
		Name:        "Wildcard Permissions",
		Description: "Roles with wildcard (*) permissions on resources or verbs",
		Category:    CategoryOverPermissive,
		Check:       checkWildcardPermissions,
	},
	{
		ID:          "RBAC004",
		Name:        "cluster-admin Usage",
		Description: "Subjects bound to cluster-admin or equivalent roles",
		Category:    CategoryOverPermissive,
		Check:       checkClusterAdminUsage,
	},
	{
		ID:          "RBAC005",
		Name:        "Secrets Access",
		Description: "Service accounts with access to secrets",
		Category:    CategorySecretAccess,
		Check:       checkSecretsAccess,
	},
	{
		ID:          "RBAC006",
		Name:        "Pod Exec Access",
		Description: "Service accounts that can exec into pods",
		Category:    CategoryPrivilegeEscalation,
		Check:       checkPodExecAccess,
	},
	{
		ID:          "RBAC007",
		Name:        "Bind/Escalate Permissions",
		Description: "Service accounts with bind or escalate verbs (can grant themselves permissions)",
		Category:    CategoryPrivilegeEscalation,
		Check:       checkBindEscalate,
	},
	{
		ID:          "RBAC008",
		Name:        "Impersonation Permissions",
		Description: "Service accounts that can impersonate other users/groups",
		Category:    CategoryPrivilegeEscalation,
		Check:       checkImpersonation,
	},
	{
		ID:          "RBAC009",
		Name:        "Cross-Namespace ClusterRoleBindings",
		Description: "ClusterRoleBindings granting access to service accounts in non-system namespaces",
		Category:    CategoryCrossNamespace,
		Check:       checkCrossNamespaceBindings,
	},
	{
		ID:          "RBAC010",
		Name:        "Unused ServiceAccounts",
		Description: "Service accounts with permissions but no workloads using them",
		Category:    CategoryUnusedAccess,
		Check:       checkUnusedServiceAccounts,
	},
	{
		ID:          "RBAC011",
		Name:        "Node/Proxy Access",
		Description: "Service accounts with node/proxy access (kubelet API access)",
		Category:    CategoryPrivilegeEscalation,
		Check:       checkNodeProxyAccess,
	},
	{
		ID:          "RBAC012",
		Name:        "CSR Permissions",
		Description: "Service accounts that can create or approve certificate signing requests",
		Category:    CategoryPrivilegeEscalation,
		Check:       checkCSRPermissions,
	},
	{
		ID:          "RBAC013",
		Name:        "Webhook Modification",
		Description: "Service accounts that can modify admission webhooks",
		Category:    CategoryPrivilegeEscalation,
		Check:       checkWebhookPermissions,
	},
	{
		ID:          "RBAC014",
		Name:        "Workload Creation Permissions",
		Description: "Service accounts that can create pods/deployments/daemonsets",
		Category:    CategoryPrivilegeEscalation,
		Check:       checkWorkloadCreation,
	},
	{
		ID:          "RBAC015",
		Name:        "Dangerous Verbs Combination",
		Description: "Roles with delete permissions on critical resources",
		Category:    CategoryOverPermissive,
		Check:       checkDangerousVerbs,
	},
	{
		ID:          "RBAC018",
		Name:        "ServiceAccount Token Create",
		Description: "Service accounts that can create tokens for other service accounts (TokenRequest API abuse)",
		Category:    CategoryPrivilegeEscalation,
		Check:       checkTokenCreate,
	},
}

// RunRBACAudit performs all security checks on the graph
func RunRBACAudit(g *graph.Graph, opts RBACAuditOptions) *RBACAuditResult {
	result := &RBACAuditResult{
		Summary: AuditSummary{
			ByCategory: make(map[FindingCategory]int),
		},
	}

	skipSet := make(map[string]bool)
	for _, s := range opts.SkipChecks {
		skipSet[s] = true
	}

	runSet := make(map[string]bool)
	for _, r := range opts.ChecksToRun {
		runSet[r] = true
	}

	for _, check := range AllChecks {
		// Skip if explicitly excluded
		if skipSet[check.ID] {
			continue
		}

		// Skip if specific checks requested and this isn't one
		if len(runSet) > 0 && !runSet[check.ID] {
			continue
		}

		result.ChecksRun = append(result.ChecksRun, check.ID)
		findings := check.Check(g, opts)

		for _, f := range findings {
			f.CheckID = check.ID
			f.Category = check.Category
			result.Findings = append(result.Findings, f)
			result.TotalFindings++

			// Update summary
			switch f.Severity {
			case graph.SeverityCritical:
				result.Summary.Critical++
			case graph.SeverityHigh:
				result.Summary.High++
			case graph.SeverityMedium:
				result.Summary.Medium++
			case graph.SeverityLow:
				result.Summary.Low++
			}
			result.Summary.ByCategory[f.Category]++
		}
	}

	// Sort findings by severity
	sort.Slice(result.Findings, func(i, j int) bool {
		return severityRank[result.Findings[i].Severity] < severityRank[result.Findings[j].Severity]
	})

	return result
}

// Individual check implementations

func checkDefaultSAUsage(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding

	workloads := g.GetNodesByType(graph.NodeWorkload)
	var affected []AffectedResource

	for _, w := range workloads {
		if opts.Namespace != "" && w.Namespace != opts.Namespace {
			continue
		}
		if !opts.IncludeSystem && collector.IsSystemNamespace(w.Namespace) {
			continue
		}

		edges := g.GetOutEdges(w.ID)
		for _, e := range edges {
			if e.Type == graph.EdgeUses {
				sa := g.GetNode(e.To)
				if sa != nil && sa.Name == "default" {
					affected = append(affected, AffectedResource{
						Kind:      w.Metadata.WorkloadKind,
						Namespace: w.Namespace,
						Name:      w.Name,
						Details:   "Uses default ServiceAccount",
					})
				}
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityMedium,
			Title:       "Workloads using default ServiceAccount",
			Description: "Workloads should use dedicated service accounts to follow least privilege principle",
			Affected:    affected,
			Remediation: "Create dedicated ServiceAccounts for each workload with only required permissions",
			References:  []string{"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/"},
		})
	}

	return findings
}

func checkAutomountTokens(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	var affected []AffectedResource

	for _, sa := range serviceAccounts {
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		// Check if SA has automount enabled (default is true)
		// and if it has any RBAC bindings
		edges := g.GetOutEdges(sa.ID)
		hasBindings := false
		for _, e := range edges {
			if e.Type == graph.EdgeBinds {
				hasBindings = true
				break
			}
		}

		// If no bindings but automount is on, it's unnecessary
		if !hasBindings && sa.Metadata.AutomountToken {
			affected = append(affected, AffectedResource{
				Kind:      "ServiceAccount",
				Namespace: sa.Namespace,
				Name:      sa.Name,
				Details:   "Has automount enabled but no RBAC bindings",
			})
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityLow,
			Title:       "ServiceAccounts with unnecessary token automount",
			Description: "Service accounts that don't need API access should disable automounting tokens",
			Affected:    affected,
			Remediation: "Set automountServiceAccountToken: false on ServiceAccount or Pod spec",
			References:  []string{"https://kubernetes.io/docs/tasks/configure-pod-container/configure-service-account/#opt-out-of-api-credential-automounting"},
		})
	}

	return findings
}

func checkWildcardPermissions(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding

	roles := g.GetNodesByType(graph.NodeRole)
	var affectedRoles []AffectedResource
	var affectedVerbs []AffectedResource

	for _, role := range roles {
		if opts.Namespace != "" && role.Namespace != opts.Namespace && !role.Metadata.IsClusterRole {
			continue
		}
		if !opts.IncludeSystem && collector.IsSystemNamespace(role.Namespace) && !role.Metadata.IsClusterRole {
			continue
		}

		edges := g.GetOutEdges(role.ID)
		for _, e := range edges {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}

			// Check for wildcard resources
			if resourceNode.Metadata.ResourceKind == "*" {
				affectedRoles = append(affectedRoles, AffectedResource{
					Kind:      roleKind(role),
					Namespace: role.Namespace,
					Name:      role.Name,
					Details:   "Has wildcard (*) resource access",
				})
			}

			// Check for wildcard verbs
			for _, v := range e.Metadata.Verbs {
				if v == "*" {
					affectedVerbs = append(affectedVerbs, AffectedResource{
						Kind:      roleKind(role),
						Namespace: role.Namespace,
						Name:      role.Name,
						Details:   "Has wildcard (*) verb on " + resourceNode.Metadata.ResourceKind,
					})
					break
				}
			}
		}
	}

	if len(affectedRoles) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "Roles with wildcard resource access",
			Description: "Roles with * resource access can access any resource type",
			Affected:    affectedRoles,
			Remediation: "Specify explicit resources instead of using wildcards",
			References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole"},
		})
	}

	if len(affectedVerbs) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityHigh,
			Title:       "Roles with wildcard verb access",
			Description: "Roles with * verb access can perform any action on resources",
			Affected:    affectedVerbs,
			Remediation: "Specify explicit verbs instead of using wildcards",
			References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#role-and-clusterrole"},
		})
	}

	return findings
}

func checkClusterAdminUsage(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	var affected []AffectedResource

	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}

		edges := g.GetOutEdges(sa.ID)
		for _, e := range edges {
			if e.Type != graph.EdgeBinds {
				continue
			}
			role := g.GetNode(e.To)
			if role == nil {
				continue
			}

			nameLower := strings.ToLower(role.Name)
			if nameLower == "cluster-admin" || nameLower == "admin" {
				affected = append(affected, AffectedResource{
					Kind:      "ServiceAccount",
					Namespace: sa.Namespace,
					Name:      sa.Name,
					Details:   "Bound to " + role.Name,
				})
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "ServiceAccounts bound to cluster-admin",
			Description: "cluster-admin grants superuser access to the entire cluster",
			Affected:    affected,
			Remediation: "Create custom roles with only required permissions",
			References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#user-facing-roles"},
		})
	}

	return findings
}

func checkSecretsAccess(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	var affected []AffectedResource

	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				if resourceNode.Metadata.ResourceKind == "secrets" || resourceNode.Metadata.ResourceKind == "*" {
					verbs := strings.Join(e.Metadata.Verbs, ", ")
					affected = append(affected, AffectedResource{
						Kind:      "ServiceAccount",
						Namespace: sa.Namespace,
						Name:      sa.Name,
						Details:   "Can " + verbs + " secrets via " + role.Name,
					})
					break
				}
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "ServiceAccounts with secrets access",
			Description: "Access to secrets can expose sensitive credentials and tokens",
			Affected:    affected,
			Remediation: "Restrict secrets access to specific secret names using resourceNames",
			References:  []string{"https://kubernetes.io/docs/concepts/configuration/secret/#best-practices"},
		})
	}

	return findings
}

func checkPodExecAccess(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	var affected []AffectedResource

	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				if resourceNode.Metadata.ResourceKind == "pods/exec" ||
					resourceNode.Metadata.ResourceKind == "pods/*" ||
					resourceNode.Metadata.ResourceKind == "*" {
					affected = append(affected, AffectedResource{
						Kind:      "ServiceAccount",
						Namespace: sa.Namespace,
						Name:      sa.Name,
						Details:   "Can exec into pods via " + role.Name,
					})
					break
				}
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityHigh,
			Title:       "ServiceAccounts with pods/exec access",
			Description: "pods/exec allows running commands inside containers, enabling lateral movement",
			Affected:    affected,
			Remediation: "Restrict pods/exec to specific pods using resourceNames or remove if not needed",
		})
	}

	return findings
}

func checkBindEscalate(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	var affectedBind []AffectedResource
	var affectedEscalate []AffectedResource

	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}

				for _, v := range e.Metadata.Verbs {
					if v == "bind" || v == "*" {
						affectedBind = append(affectedBind, AffectedResource{
							Kind:      "ServiceAccount",
							Namespace: sa.Namespace,
							Name:      sa.Name,
							Details:   "Has 'bind' verb via " + role.Name,
						})
					}
					if v == "escalate" || v == "*" {
						affectedEscalate = append(affectedEscalate, AffectedResource{
							Kind:      "ServiceAccount",
							Namespace: sa.Namespace,
							Name:      sa.Name,
							Details:   "Has 'escalate' verb via " + role.Name,
						})
					}
				}
			}
		}
	}

	if len(affectedBind) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "ServiceAccounts with 'bind' permission",
			Description: "The 'bind' verb allows binding any role/clusterrole, bypassing RBAC escalation protection",
			Affected:    affectedBind,
			Remediation: "Remove bind permission and use specific role bindings instead",
			References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-binding-creation-or-update"},
		})
	}

	if len(affectedEscalate) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "ServiceAccounts with 'escalate' permission",
			Description: "The 'escalate' verb allows creating roles with more permissions than the creator has",
			Affected:    affectedEscalate,
			Remediation: "Remove escalate permission - it should almost never be needed",
			References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/rbac/#restrictions-on-role-creation-or-update"},
		})
	}

	return findings
}

func checkImpersonation(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	var affected []AffectedResource

	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				kind := resourceNode.Metadata.ResourceKind
				if kind == "users" || kind == "groups" || kind == "serviceaccounts" || kind == "*" {
					for _, v := range e.Metadata.Verbs {
						if v == "impersonate" || v == "*" {
							affected = append(affected, AffectedResource{
								Kind:      "ServiceAccount",
								Namespace: sa.Namespace,
								Name:      sa.Name,
								Details:   "Can impersonate " + kind + " via " + role.Name,
							})
							break
						}
					}
				}
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "ServiceAccounts with impersonation permissions",
			Description: "Impersonation allows acting as other users/groups including system:masters",
			Affected:    affected,
			Remediation: "Remove impersonation permissions or restrict to specific identities using resourceNames",
			References:  []string{"https://kubernetes.io/docs/reference/access-authn-authz/authentication/#user-impersonation"},
		})
	}

	return findings
}

func checkCrossNamespaceBindings(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding
	var affected []AffectedResource

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		edges := g.GetOutEdges(sa.ID)
		for _, e := range edges {
			if e.Type != graph.EdgeBinds {
				continue
			}

			role := g.GetNode(e.To)
			if role == nil {
				continue
			}

			// Check if this is a ClusterRoleBinding
			if e.Metadata.IsClusterBinding && role.Metadata.IsClusterRole {
				affected = append(affected, AffectedResource{
					Kind:      "ServiceAccount",
					Namespace: sa.Namespace,
					Name:      sa.Name,
					Details:   "Has ClusterRoleBinding to " + role.Name,
				})
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityMedium,
			Title:       "ServiceAccounts with ClusterRoleBindings",
			Description: "Non-system ServiceAccounts with ClusterRoleBindings have cluster-wide permissions",
			Affected:    affected,
			Remediation: "Use namespace-scoped RoleBindings when possible to limit blast radius",
		})
	}

	return findings
}

func checkUnusedServiceAccounts(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding
	var affected []AffectedResource

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}
		if sa.Name == "default" {
			continue // Skip default SA
		}

		// Check if SA has any bindings (permissions)
		edges := g.GetOutEdges(sa.ID)
		hasBindings := false
		for _, e := range edges {
			if e.Type == graph.EdgeBinds {
				hasBindings = true
				break
			}
		}

		if !hasBindings {
			continue // No permissions, not a risk
		}

		// Check if any workloads use this SA
		workloads := g.GetWorkloadsUsingSA(sa.ID)
		if len(workloads) == 0 {
			affected = append(affected, AffectedResource{
				Kind:      "ServiceAccount",
				Namespace: sa.Namespace,
				Name:      sa.Name,
				Details:   "Has RBAC bindings but no workloads using it",
			})
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityLow,
			Title:       "Unused ServiceAccounts with permissions",
			Description: "Service accounts with RBAC bindings but no workloads represent unnecessary attack surface",
			Affected:    affected,
			Remediation: "Remove unused service accounts and their role bindings",
		})
	}

	return findings
}

func checkNodeProxyAccess(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding
	var affected []AffectedResource

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				if resourceNode.Metadata.ResourceKind == "nodes/proxy" || resourceNode.Metadata.ResourceKind == "*" {
					affected = append(affected, AffectedResource{
						Kind:      "ServiceAccount",
						Namespace: sa.Namespace,
						Name:      sa.Name,
						Details:   "Has nodes/proxy access via " + role.Name,
					})
					break
				}
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "ServiceAccounts with nodes/proxy access",
			Description: "nodes/proxy allows direct access to kubelet API, bypassing pod-level RBAC",
			Affected:    affected,
			Remediation: "Remove nodes/proxy access - use pods/exec with proper RBAC instead",
			References:  []string{"https://blog.aquasec.com/privilege-escalation-kubernetes-rbac"},
		})
	}

	return findings
}

func checkCSRPermissions(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding
	var affectedCreate []AffectedResource
	var affectedApprove []AffectedResource

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				kind := resourceNode.Metadata.ResourceKind
				if kind == "certificatesigningrequests" || kind == "*" {
					if containsString(e.Metadata.Verbs, "create") || containsString(e.Metadata.Verbs, "*") {
						affectedCreate = append(affectedCreate, AffectedResource{
							Kind:      "ServiceAccount",
							Namespace: sa.Namespace,
							Name:      sa.Name,
							Details:   "Can create CSRs via " + role.Name,
						})
					}
				}
				if kind == "certificatesigningrequests/approval" || kind == "*" {
					if containsString(e.Metadata.Verbs, "update") || containsString(e.Metadata.Verbs, "*") {
						affectedApprove = append(affectedApprove, AffectedResource{
							Kind:      "ServiceAccount",
							Namespace: sa.Namespace,
							Name:      sa.Name,
							Details:   "Can approve CSRs via " + role.Name,
						})
					}
				}
			}
		}
	}

	if len(affectedCreate) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityHigh,
			Title:       "ServiceAccounts that can create CSRs",
			Description: "Can create certificate signing requests for any identity",
			Affected:    affectedCreate,
			Remediation: "Restrict CSR creation to specific signers using resourceNames",
		})
	}

	if len(affectedApprove) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "ServiceAccounts that can approve CSRs",
			Description: "Can approve CSRs to issue certificates for any identity",
			Affected:    affectedApprove,
			Remediation: "CSR approval should be limited to trusted automation only",
		})
	}

	return findings
}

func checkWebhookPermissions(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding
	var affected []AffectedResource

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				kind := resourceNode.Metadata.ResourceKind
				if kind == "validatingwebhookconfigurations" ||
					kind == "mutatingwebhookconfigurations" ||
					kind == "*" {
					if containsString(e.Metadata.Verbs, "create") ||
						containsString(e.Metadata.Verbs, "update") ||
						containsString(e.Metadata.Verbs, "patch") ||
						containsString(e.Metadata.Verbs, "*") {
						affected = append(affected, AffectedResource{
							Kind:      "ServiceAccount",
							Namespace: sa.Namespace,
							Name:      sa.Name,
							Details:   "Can modify " + kind + " via " + role.Name,
						})
					}
				}
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityCritical,
			Title:       "ServiceAccounts that can modify webhooks",
			Description: "Admission webhooks can intercept and modify all API requests",
			Affected:    affected,
			Remediation: "Webhook modification should be restricted to cluster administrators",
		})
	}

	return findings
}

func checkWorkloadCreation(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding
	var affected []AffectedResource

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		canCreate := []string{}

		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				kind := resourceNode.Metadata.ResourceKind
				workloadKinds := []string{"pods", "deployments", "daemonsets", "statefulsets", "jobs", "cronjobs", "*"}

				if containsString(e.Metadata.Verbs, "create") || containsString(e.Metadata.Verbs, "*") {
					for _, wk := range workloadKinds {
						if kind == wk {
							if !containsString(canCreate, kind) {
								canCreate = append(canCreate, kind)
							}
						}
					}
				}
			}
		}

		if len(canCreate) > 0 {
			affected = append(affected, AffectedResource{
				Kind:      "ServiceAccount",
				Namespace: sa.Namespace,
				Name:      sa.Name,
				Details:   "Can create: " + strings.Join(canCreate, ", "),
			})
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityHigh,
			Title:       "ServiceAccounts that can create workloads",
			Description: "Workload creation allows running arbitrary containers with any ServiceAccount",
			Affected:    affected,
			Remediation: "Use Pod Security Standards to restrict privileged container creation",
			References:  []string{"https://kubernetes.io/docs/concepts/security/pod-security-standards/"},
		})
	}

	return findings
}

func checkDangerousVerbs(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding
	var affected []AffectedResource

	dangerousResources := map[string]bool{
		"nodes":            true,
		"namespaces":       true,
		"persistentvolumes": true,
		"storageclasses":   true,
	}

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				kind := resourceNode.Metadata.ResourceKind
				if dangerousResources[kind] || kind == "*" {
					if containsString(e.Metadata.Verbs, "delete") ||
						containsString(e.Metadata.Verbs, "deletecollection") ||
						containsString(e.Metadata.Verbs, "*") {
						affected = append(affected, AffectedResource{
							Kind:      "ServiceAccount",
							Namespace: sa.Namespace,
							Name:      sa.Name,
							Details:   "Can delete " + kind + " via " + role.Name,
						})
					}
				}
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityHigh,
			Title:       "ServiceAccounts with delete on critical resources",
			Description: "Delete permissions on nodes, namespaces, or PVs can cause cluster-wide disruption",
			Affected:    affected,
			Remediation: "Remove delete permissions on critical cluster resources",
		})
	}

	return findings
}

// Helper functions

func roleKind(role *graph.Node) string {
	if role.Metadata.IsClusterRole {
		return "ClusterRole"
	}
	return "Role"
}
