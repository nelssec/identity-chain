package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// AttackTechnique represents a specific attack technique in the chain
type AttackTechnique string

const (
	TechniqueInitialAccess       AttackTechnique = "initial_access"
	TechniqueSecretsAccess       AttackTechnique = "secrets_access"
	TechniqueCredentialTheft     AttackTechnique = "credential_theft"
	TechniqueIdentityAssumption  AttackTechnique = "identity_assumption"
	TechniquePodExec             AttackTechnique = "pod_exec"
	TechniquePodCreation         AttackTechnique = "pod_creation"
	TechniquePrivilegeEscalation AttackTechnique = "privilege_escalation"
	TechniqueCloudAccess         AttackTechnique = "cloud_access"
	TechniqueCloudPrivesc        AttackTechnique = "cloud_privesc"
	TechniqueLateralMovement     AttackTechnique = "lateral_movement"
	TechniqueDataExfiltration    AttackTechnique = "data_exfiltration"
	TechniqueClusterTakeover     AttackTechnique = "cluster_takeover"
)

// TechniqueInfo provides details about attack techniques
var TechniqueInfo = map[AttackTechnique]struct {
	Name        string
	Description string
	MitreID     string // MITRE ATT&CK ID
	Severity    graph.Severity
}{
	TechniqueInitialAccess: {
		Name:        "Initial Access",
		Description: "Attacker gains initial foothold in the workload",
		MitreID:     "T1190",
		Severity:    graph.SeverityMedium,
	},
	TechniqueSecretsAccess: {
		Name:        "Secrets Access",
		Description: "Read Kubernetes secrets containing credentials or sensitive data",
		MitreID:     "T1552.007",
		Severity:    graph.SeverityCritical,
	},
	TechniqueCredentialTheft: {
		Name:        "Credential Theft",
		Description: "Steal service account tokens or other credentials",
		MitreID:     "T1528",
		Severity:    graph.SeverityCritical,
	},
	TechniqueIdentityAssumption: {
		Name:        "Identity Assumption",
		Description: "Use stolen credentials to assume another identity",
		MitreID:     "T1550",
		Severity:    graph.SeverityHigh,
	},
	TechniquePodExec: {
		Name:        "Container Execution",
		Description: "Execute commands in other containers via kubectl exec",
		MitreID:     "T1609",
		Severity:    graph.SeverityHigh,
	},
	TechniquePodCreation: {
		Name:        "Container Deployment",
		Description: "Create pods with different service accounts or privileged configurations",
		MitreID:     "T1610",
		Severity:    graph.SeverityHigh,
	},
	TechniquePrivilegeEscalation: {
		Name:        "Privilege Escalation",
		Description: "Escalate privileges via RBAC manipulation or other vectors",
		MitreID:     "T1078.004",
		Severity:    graph.SeverityCritical,
	},
	TechniqueCloudAccess: {
		Name:        "Cloud Resource Access",
		Description: "Access cloud resources via IRSA/Workload Identity",
		MitreID:     "T1078.004",
		Severity:    graph.SeverityHigh,
	},
	TechniqueCloudPrivesc: {
		Name:        "Cloud Privilege Escalation",
		Description: "Escalate privileges within cloud IAM",
		MitreID:     "T1098",
		Severity:    graph.SeverityCritical,
	},
	TechniqueLateralMovement: {
		Name:        "Lateral Movement",
		Description: "Move to other workloads or namespaces",
		MitreID:     "T1021",
		Severity:    graph.SeverityHigh,
	},
	TechniqueDataExfiltration: {
		Name:        "Data Exfiltration",
		Description: "Access and exfiltrate sensitive data",
		MitreID:     "T1567",
		Severity:    graph.SeverityCritical,
	},
	TechniqueClusterTakeover: {
		Name:        "Cluster Takeover",
		Description: "Gain cluster-admin or equivalent access",
		MitreID:     "T1098",
		Severity:    graph.SeverityCritical,
	},
}

// AttackPathStep represents a single step in an attack path
type AttackPathStep struct {
	StepNumber  int             `json:"step_number"`
	Technique   AttackTechnique `json:"technique"`
	FromNode    *graph.Node     `json:"from_node,omitempty"`
	ToNode      *graph.Node     `json:"to_node,omitempty"`
	Action      string          `json:"action"`
	Description string          `json:"description"`
	Details     []string        `json:"details,omitempty"`
	Severity    graph.Severity  `json:"severity"`
	ViaRole     string          `json:"via_role,omitempty"`
	Verbs       []string        `json:"verbs,omitempty"`
	MitreID     string          `json:"mitre_id,omitempty"`
}

// AttackPath represents a complete attack path from entry point to objective
type AttackPath struct {
	ID               string           `json:"id"`
	Name             string           `json:"name"`
	Description      string           `json:"description"`
	EntryPoint       *graph.Node      `json:"entry_point"`
	Objective        string           `json:"objective"`
	Steps            []AttackPathStep `json:"steps"`
	MaxSeverity      graph.Severity   `json:"max_severity"`
	AffectsCloud     bool             `json:"affects_cloud"`
	AffectsCluster   bool             `json:"affects_cluster"`
	CrossesNamespace bool             `json:"crosses_namespace"`
	RiskScore        int              `json:"risk_score"`
	Mitigations      []string         `json:"mitigations,omitempty"`
}

// AttackPathResult contains all attack paths from analysis
type AttackPathResult struct {
	SourceWorkload    *graph.Node   `json:"source_workload,omitempty"`
	TotalPaths        int           `json:"total_paths"`
	CriticalPaths     int           `json:"critical_paths"`
	HighPaths         int           `json:"high_paths"`
	Paths             []*AttackPath `json:"paths"`
	MaxSeverity       graph.Severity `json:"max_severity"`
	CanReachCloud     bool          `json:"can_reach_cloud"`
	CanReachCluster   bool          `json:"can_reach_cluster"`
	UniqueObjectives  []string      `json:"unique_objectives"`
	TopTechniques     []TechniqueCount `json:"top_techniques"`
}

// TechniqueCount tracks how often a technique appears
type TechniqueCount struct {
	Technique AttackTechnique `json:"technique"`
	Name      string          `json:"name"`
	Count     int             `json:"count"`
}

// AttackPathOptions configures the attack path analysis
type AttackPathOptions struct {
	MaxDepth       int
	IncludeCloud   bool
	IncludePrivesc bool
	Namespace      string
}

// FindAttackPaths discovers all attack paths from a given workload
func FindAttackPaths(g *graph.Graph, workloadID string, opts AttackPathOptions) (*AttackPathResult, error) {
	workload := g.GetNode(workloadID)
	if workload == nil {
		return nil, fmt.Errorf("workload not found: %s", workloadID)
	}

	if opts.MaxDepth == 0 {
		opts.MaxDepth = 5
	}

	result := &AttackPathResult{
		SourceWorkload: workload,
		MaxSeverity:    graph.SeverityLow,
	}

	// Find the service account for this workload
	var saNode *graph.Node
	for _, e := range g.GetOutEdges(workloadID) {
		if e.Type == graph.EdgeUses {
			saNode = g.GetNode(e.To)
			break
		}
	}

	if saNode == nil {
		return result, nil
	}

	// Collect all roles bound to this SA
	roles := collectBoundRoles(g, saNode.ID)

	// Find attack paths
	var paths []*AttackPath
	objectives := make(map[string]bool)
	techniqueCounts := make(map[AttackTechnique]int)

	// 1. Secrets access paths
	secretsPaths := findSecretsAccessPaths(g, workload, saNode, roles)
	for _, p := range secretsPaths {
		paths = append(paths, p)
		objectives[p.Objective] = true
		for _, s := range p.Steps {
			techniqueCounts[s.Technique]++
		}
	}

	// 2. Pod exec / lateral movement paths
	execPaths := findPodExecPaths(g, workload, saNode, roles)
	for _, p := range execPaths {
		paths = append(paths, p)
		objectives[p.Objective] = true
		for _, s := range p.Steps {
			techniqueCounts[s.Technique]++
		}
	}

	// 3. Pod creation paths (identity assumption)
	podCreationPaths := findPodCreationPaths(g, workload, saNode, roles)
	for _, p := range podCreationPaths {
		paths = append(paths, p)
		objectives[p.Objective] = true
		for _, s := range p.Steps {
			techniqueCounts[s.Technique]++
		}
	}

	// 4. Cloud access paths
	if opts.IncludeCloud {
		cloudPaths := findCloudAccessPaths(g, workload, saNode, roles)
		for _, p := range cloudPaths {
			paths = append(paths, p)
			objectives[p.Objective] = true
			result.CanReachCloud = true
			for _, s := range p.Steps {
				techniqueCounts[s.Technique]++
			}
		}
	}

	// 5. Privilege escalation paths
	if opts.IncludePrivesc {
		privescPaths := findPrivescAttackPaths(g, workload, saNode, roles)
		for _, p := range privescPaths {
			paths = append(paths, p)
			objectives[p.Objective] = true
			if p.AffectsCluster {
				result.CanReachCluster = true
			}
			for _, s := range p.Steps {
				techniqueCounts[s.Technique]++
			}
		}
	}

	// Calculate statistics
	for _, p := range paths {
		if p.MaxSeverity == graph.SeverityCritical {
			result.CriticalPaths++
		} else if p.MaxSeverity == graph.SeverityHigh {
			result.HighPaths++
		}
		updateAttackPathMaxSeverity(result, p.MaxSeverity)
	}

	result.Paths = paths
	result.TotalPaths = len(paths)

	// Unique objectives
	for obj := range objectives {
		result.UniqueObjectives = append(result.UniqueObjectives, obj)
	}
	sort.Strings(result.UniqueObjectives)

	// Top techniques
	for tech, count := range techniqueCounts {
		info := TechniqueInfo[tech]
		result.TopTechniques = append(result.TopTechniques, TechniqueCount{
			Technique: tech,
			Name:      info.Name,
			Count:     count,
		})
	}
	sort.Slice(result.TopTechniques, func(i, j int) bool {
		return result.TopTechniques[i].Count > result.TopTechniques[j].Count
	})

	// Sort paths by severity
	sort.Slice(result.Paths, func(i, j int) bool {
		iScore := severityValue[result.Paths[i].MaxSeverity]
		jScore := severityValue[result.Paths[j].MaxSeverity]
		if iScore != jScore {
			return iScore > jScore
		}
		return result.Paths[i].RiskScore > result.Paths[j].RiskScore
	})

	return result, nil
}

// FindAllAttackPaths analyzes all workloads in the graph
func FindAllAttackPaths(g *graph.Graph, opts AttackPathOptions) ([]*AttackPathResult, error) {
	workloads := g.GetNodesByType(graph.NodeWorkload)
	results := make([]*AttackPathResult, 0)

	for _, w := range workloads {
		// Skip system namespaces if not included
		if !opts.IncludeCloud && isSystemNamespace(w.Namespace) {
			continue
		}

		// Filter by namespace if specified
		if opts.Namespace != "" && w.Namespace != opts.Namespace {
			continue
		}

		result, err := FindAttackPaths(g, w.ID, opts)
		if err != nil {
			continue
		}
		if result != nil && len(result.Paths) > 0 {
			results = append(results, result)
		}
	}

	// Sort by severity and path count
	sort.Slice(results, func(i, j int) bool {
		iScore := severityValue[results[i].MaxSeverity]
		jScore := severityValue[results[j].MaxSeverity]
		if iScore != jScore {
			return iScore > jScore
		}
		return results[i].TotalPaths > results[j].TotalPaths
	})

	return results, nil
}

// findSecretsAccessPaths finds paths to access secrets
func findSecretsAccessPaths(g *graph.Graph, workload, sa *graph.Node, roles []*graph.Node) []*AttackPath {
	var paths []*AttackPath
	pathID := 1

	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil || resourceNode.Metadata.ResourceKind != "secrets" {
				continue
			}

			hasRead := false
			for _, v := range e.Metadata.Verbs {
				if v == "get" || v == "list" || v == "watch" || v == "*" {
					hasRead = true
					break
				}
			}

			if !hasRead {
				continue
			}

			scope := "namespace-scoped"
			if role.Metadata.IsClusterRole {
				scope = "cluster-wide"
			}

			path := &AttackPath{
				ID:          fmt.Sprintf("secrets-%d", pathID),
				Name:        "Secrets Access via " + role.Name,
				Description: fmt.Sprintf("Access %s secrets through RBAC permissions", scope),
				EntryPoint:  workload,
				Objective:   "Read Kubernetes Secrets",
				MaxSeverity: graph.SeverityCritical,
				RiskScore:   90,
				Steps: []AttackPathStep{
					{
						StepNumber:  1,
						Technique:   TechniqueInitialAccess,
						FromNode:    nil,
						ToNode:      workload,
						Action:      "Compromise workload",
						Description: fmt.Sprintf("Attacker gains access to %s/%s", workload.Namespace, workload.Name),
						Severity:    graph.SeverityMedium,
						MitreID:     "T1190",
					},
					{
						StepNumber:  2,
						Technique:   TechniqueSecretsAccess,
						FromNode:    sa,
						ToNode:      resourceNode,
						Action:      "Read secrets",
						Description: fmt.Sprintf("Use SA %s to read secrets %s", sa.Name, scope),
						Details:     []string{fmt.Sprintf("Via role: %s", role.Name), fmt.Sprintf("Verbs: %s", strings.Join(e.Metadata.Verbs, ", "))},
						Severity:    graph.SeverityCritical,
						ViaRole:     role.Name,
						Verbs:       e.Metadata.Verbs,
						MitreID:     "T1552.007",
					},
				},
				Mitigations: []string{
					"Restrict secrets access to specific secret names using resourceNames",
					"Use external secrets management (Vault, AWS Secrets Manager)",
					"Enable audit logging for secrets access",
				},
			}

			if role.Metadata.IsClusterRole {
				path.AffectsCluster = true
				path.Steps = append(path.Steps, AttackPathStep{
					StepNumber:  3,
					Technique:   TechniqueCredentialTheft,
					Action:      "Steal SA tokens",
					Description: "Read other service account tokens from cluster-wide secrets",
					Severity:    graph.SeverityCritical,
					MitreID:     "T1528",
				})
				path.RiskScore = 100
			}

			paths = append(paths, path)
			pathID++
		}
	}

	return paths
}

// findPodExecPaths finds lateral movement paths via pod exec
func findPodExecPaths(g *graph.Graph, workload, sa *graph.Node, roles []*graph.Node) []*AttackPath {
	var paths []*AttackPath
	pathID := 1

	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil || resourceNode.Metadata.ResourceKind != "pods/exec" {
				continue
			}

			hasExec := false
			for _, v := range e.Metadata.Verbs {
				if v == "create" || v == "get" || v == "*" {
					hasExec = true
					break
				}
			}

			if !hasExec {
				continue
			}

			scope := "namespace"
			if role.Metadata.IsClusterRole {
				scope = "any namespace"
			}

			path := &AttackPath{
				ID:          fmt.Sprintf("exec-%d", pathID),
				Name:        "Lateral Movement via Pod Exec",
				Description: fmt.Sprintf("Execute commands in other pods in %s", scope),
				EntryPoint:  workload,
				Objective:   "Lateral Movement to Other Pods",
				MaxSeverity: graph.SeverityHigh,
				RiskScore:   75,
				Steps: []AttackPathStep{
					{
						StepNumber:  1,
						Technique:   TechniqueInitialAccess,
						ToNode:      workload,
						Action:      "Compromise workload",
						Description: fmt.Sprintf("Attacker gains access to %s/%s", workload.Namespace, workload.Name),
						Severity:    graph.SeverityMedium,
						MitreID:     "T1190",
					},
					{
						StepNumber:  2,
						Technique:   TechniquePodExec,
						FromNode:    sa,
						Action:      "Exec into pods",
						Description: fmt.Sprintf("Use pods/exec permissions to run commands in other pods in %s", scope),
						Details:     []string{fmt.Sprintf("Via role: %s", role.Name)},
						Severity:    graph.SeverityHigh,
						ViaRole:     role.Name,
						MitreID:     "T1609",
					},
					{
						StepNumber:  3,
						Technique:   TechniqueLateralMovement,
						Action:      "Move laterally",
						Description: "Access data, tokens, or pivot to other service accounts",
						Severity:    graph.SeverityHigh,
						MitreID:     "T1021",
					},
				},
				Mitigations: []string{
					"Restrict pods/exec access to specific pods using resourceNames",
					"Use admission webhooks to limit exec access",
					"Enable pod security policies to prevent privilege escalation in target pods",
				},
			}

			if role.Metadata.IsClusterRole {
				path.AffectsCluster = true
				path.CrossesNamespace = true
				path.RiskScore = 85
			}

			paths = append(paths, path)
			pathID++
		}
	}

	return paths
}

// findPodCreationPaths finds identity assumption paths via pod creation
func findPodCreationPaths(g *graph.Graph, workload, sa *graph.Node, roles []*graph.Node) []*AttackPath {
	var paths []*AttackPath
	pathID := 1

	canCreate := false
	var createRole *graph.Node
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
			if kind != "pods" && kind != "deployments" && kind != "daemonsets" && kind != "replicasets" && kind != "jobs" && kind != "cronjobs" && kind != "*" {
				continue
			}
			for _, v := range e.Metadata.Verbs {
				if v == "create" || v == "*" {
					canCreate = true
					createRole = role
					break
				}
			}
		}
	}

	if !canCreate {
		return paths
	}

	// Find other SAs in the same namespace (or cluster-wide)
	allSAs := g.GetNodesByType(graph.NodeServiceAccount)
	for _, otherSA := range allSAs {
		if otherSA.ID == sa.ID {
			continue
		}

		// Check namespace scope
		if !createRole.Metadata.IsClusterRole && otherSA.Namespace != sa.Namespace {
			continue
		}

		// Check if the other SA has interesting permissions
		otherRoles := collectBoundRoles(g, otherSA.ID)
		hasInteresting := false
		var interestingPerms []string

		for _, otherRole := range otherRoles {
			for _, e := range g.GetOutEdges(otherRole.ID) {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resNode := g.GetNode(e.To)
				if resNode == nil {
					continue
				}
				kind := resNode.Metadata.ResourceKind
				if kind == "secrets" || kind == "pods/exec" || kind == "*" {
					hasInteresting = true
					interestingPerms = append(interestingPerms, fmt.Sprintf("%s via %s", kind, otherRole.Name))
				}
			}
		}

		// Check for cloud identity
		if otherSA.HasCloudIdentity() {
			hasInteresting = true
			interestingPerms = append(interestingPerms, fmt.Sprintf("Cloud: %s", otherSA.Metadata.CloudRoleARN))
		}

		if !hasInteresting {
			continue
		}

		path := &AttackPath{
			ID:          fmt.Sprintf("pod-create-%d", pathID),
			Name:        fmt.Sprintf("Identity Assumption: %s", otherSA.Name),
			Description: fmt.Sprintf("Create pod with SA %s to inherit its permissions", otherSA.Name),
			EntryPoint:  workload,
			Objective:   "Assume Higher-Privilege Identity",
			MaxSeverity: graph.SeverityHigh,
			RiskScore:   80,
			Steps: []AttackPathStep{
				{
					StepNumber:  1,
					Technique:   TechniqueInitialAccess,
					ToNode:      workload,
					Action:      "Compromise workload",
					Description: fmt.Sprintf("Attacker gains access to %s/%s", workload.Namespace, workload.Name),
					Severity:    graph.SeverityMedium,
					MitreID:     "T1190",
				},
				{
					StepNumber:  2,
					Technique:   TechniquePodCreation,
					FromNode:    sa,
					ToNode:      otherSA,
					Action:      "Create pod with target SA",
					Description: fmt.Sprintf("Create pod using serviceAccountName: %s", otherSA.Name),
					Details:     []string{fmt.Sprintf("Via role: %s", createRole.Name)},
					Severity:    graph.SeverityHigh,
					ViaRole:     createRole.Name,
					MitreID:     "T1610",
				},
				{
					StepNumber:  3,
					Technique:   TechniqueIdentityAssumption,
					FromNode:    otherSA,
					Action:      "Inherit permissions",
					Description: fmt.Sprintf("Attacker now has access to: %s", strings.Join(interestingPerms, ", ")),
					Details:     interestingPerms,
					Severity:    graph.SeverityHigh,
					MitreID:     "T1550",
				},
			},
			Mitigations: []string{
				"Use admission webhooks to restrict serviceAccountName in pod specs",
				"Implement least-privilege for pod creation permissions",
				"Use namespace isolation to limit SA visibility",
			},
		}

		if otherSA.Namespace != sa.Namespace {
			path.CrossesNamespace = true
		}

		if otherSA.HasCloudIdentity() {
			path.AffectsCloud = true
			path.MaxSeverity = graph.SeverityCritical
			path.RiskScore = 95
		}

		paths = append(paths, path)
		pathID++
	}

	return paths
}

// findCloudAccessPaths finds paths to cloud resources
func findCloudAccessPaths(g *graph.Graph, workload, sa *graph.Node, roles []*graph.Node) []*AttackPath {
	var paths []*AttackPath
	pathID := 1

	// Check for direct cloud access via IRSA/Workload Identity
	for _, e := range g.GetOutEdges(sa.ID) {
		if e.Type != graph.EdgeAssumes {
			continue
		}

		cloudRole := g.GetNode(e.To)
		if cloudRole == nil {
			continue
		}

		severity := graph.SeverityHigh
		objective := "Access Cloud Resources"
		details := []string{fmt.Sprintf("Provider: %s", e.Metadata.CloudProvider), fmt.Sprintf("Role: %s", e.Metadata.RoleARN)}

		// Check for admin policies
		isAdmin := false
		for _, policy := range cloudRole.Metadata.CloudPolicies {
			if policy.IsAdmin {
				isAdmin = true
				severity = graph.SeverityCritical
				objective = "Full Cloud Account Access"
				details = append(details, fmt.Sprintf("ADMIN policy: %s", policy.Name))
			}
		}

		path := &AttackPath{
			ID:           fmt.Sprintf("cloud-%d", pathID),
			Name:         fmt.Sprintf("Cloud Access: %s", shortARN(e.Metadata.RoleARN)),
			Description:  fmt.Sprintf("Access cloud resources via %s", e.Metadata.CloudProvider),
			EntryPoint:   workload,
			Objective:    objective,
			MaxSeverity:  severity,
			AffectsCloud: true,
			RiskScore:    85,
			Steps: []AttackPathStep{
				{
					StepNumber:  1,
					Technique:   TechniqueInitialAccess,
					ToNode:      workload,
					Action:      "Compromise workload",
					Description: fmt.Sprintf("Attacker gains access to %s/%s", workload.Namespace, workload.Name),
					Severity:    graph.SeverityMedium,
					MitreID:     "T1190",
				},
				{
					StepNumber:  2,
					Technique:   TechniqueCloudAccess,
					FromNode:    sa,
					ToNode:      cloudRole,
					Action:      "Assume cloud role",
					Description: fmt.Sprintf("Use projected SA token to assume %s role", e.Metadata.CloudProvider),
					Details:     details,
					Severity:    graph.SeverityHigh,
					MitreID:     "T1078.004",
				},
			},
			Mitigations: []string{
				"Limit cloud IAM role permissions to least privilege",
				"Use condition keys to restrict role assumption",
				"Enable cloud audit logging (CloudTrail, Cloud Audit Logs)",
			},
		}

		if isAdmin {
			path.RiskScore = 100
			path.Steps = append(path.Steps, AttackPathStep{
				StepNumber:  3,
				Technique:   TechniqueCloudPrivesc,
				FromNode:    cloudRole,
				Action:      "Full cloud access",
				Description: "Role has admin-level permissions - can access all cloud resources",
				Severity:    graph.SeverityCritical,
				MitreID:     "T1098",
			})
		} else {
			// Add data exfiltration step for non-admin access
			path.Steps = append(path.Steps, AttackPathStep{
				StepNumber:  3,
				Technique:   TechniqueDataExfiltration,
				Action:      "Access cloud data",
				Description: "Access S3 buckets, secrets, databases, or other cloud resources",
				Severity:    graph.SeverityHigh,
				MitreID:     "T1567",
			})
		}

		paths = append(paths, path)
		pathID++
	}

	return paths
}

// findPrivescAttackPaths finds privilege escalation attack paths
func findPrivescAttackPaths(g *graph.Graph, workload, sa *graph.Node, roles []*graph.Node) []*AttackPath {
	var paths []*AttackPath
	pathID := 1

	// Check for RBAC escalation capabilities
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
			var path *AttackPath

			// Check for rolebinding creation
			if (kind == "rolebindings" || kind == "clusterrolebindings" || kind == "*") &&
				hasVerbMatch(e.Metadata.Verbs, []string{"create", "update", "patch", "*"}) {

				path = &AttackPath{
					ID:             fmt.Sprintf("privesc-bind-%d", pathID),
					Name:           "RBAC Privilege Escalation",
					Description:    "Create rolebindings to grant self elevated permissions",
					EntryPoint:     workload,
					Objective:      "Cluster Admin Access",
					MaxSeverity:    graph.SeverityCritical,
					AffectsCluster: true,
					RiskScore:      100,
					Steps: []AttackPathStep{
						{
							StepNumber:  1,
							Technique:   TechniqueInitialAccess,
							ToNode:      workload,
							Action:      "Compromise workload",
							Description: fmt.Sprintf("Attacker gains access to %s/%s", workload.Namespace, workload.Name),
							Severity:    graph.SeverityMedium,
							MitreID:     "T1190",
						},
						{
							StepNumber:  2,
							Technique:   TechniquePrivilegeEscalation,
							FromNode:    sa,
							Action:      "Create RoleBinding",
							Description: fmt.Sprintf("Create %s binding cluster-admin to current SA", kind),
							Details:     []string{fmt.Sprintf("Via role: %s", role.Name)},
							Severity:    graph.SeverityCritical,
							ViaRole:     role.Name,
							MitreID:     "T1078.004",
						},
						{
							StepNumber:  3,
							Technique:   TechniqueClusterTakeover,
							Action:      "Cluster admin access",
							Description: "Full control over Kubernetes cluster",
							Severity:    graph.SeverityCritical,
							MitreID:     "T1098",
						},
					},
					Mitigations: []string{
						"Remove ability to create/modify RoleBindings",
						"Use admission webhooks to prevent self-escalation",
						"Enable RBAC auditing",
					},
				}
			}

			// Check for impersonation
			if (kind == "users" || kind == "groups" || kind == "serviceaccounts" || kind == "*") &&
				hasVerbMatch(e.Metadata.Verbs, []string{"impersonate", "*"}) {

				path = &AttackPath{
					ID:             fmt.Sprintf("privesc-impersonate-%d", pathID),
					Name:           "User Impersonation",
					Description:    "Impersonate system:masters or admin users",
					EntryPoint:     workload,
					Objective:      "Cluster Admin Access",
					MaxSeverity:    graph.SeverityCritical,
					AffectsCluster: true,
					RiskScore:      100,
					Steps: []AttackPathStep{
						{
							StepNumber:  1,
							Technique:   TechniqueInitialAccess,
							ToNode:      workload,
							Action:      "Compromise workload",
							Description: fmt.Sprintf("Attacker gains access to %s/%s", workload.Namespace, workload.Name),
							Severity:    graph.SeverityMedium,
							MitreID:     "T1190",
						},
						{
							StepNumber:  2,
							Technique:   TechniqueIdentityAssumption,
							FromNode:    sa,
							Action:      "Impersonate admin",
							Description: "Use impersonate verb to assume system:masters identity",
							Details:     []string{fmt.Sprintf("Via role: %s", role.Name), fmt.Sprintf("Can impersonate: %s", kind)},
							Severity:    graph.SeverityCritical,
							ViaRole:     role.Name,
							MitreID:     "T1550",
						},
						{
							StepNumber:  3,
							Technique:   TechniqueClusterTakeover,
							Action:      "Full cluster access",
							Description: "Execute any API call as system:masters",
							Severity:    graph.SeverityCritical,
							MitreID:     "T1098",
						},
					},
					Mitigations: []string{
						"Remove impersonate permissions",
						"If impersonation is needed, restrict to specific identities",
						"Enable audit logging for impersonation events",
					},
				}
			}

			// Check for nodes/proxy access
			if (kind == "nodes/proxy" || kind == "*") &&
				hasVerbMatch(e.Metadata.Verbs, []string{"create", "get", "*"}) {

				path = &AttackPath{
					ID:             fmt.Sprintf("privesc-nodeproxy-%d", pathID),
					Name:           "Node Proxy Access",
					Description:    "Access kubelet API to control pods on nodes",
					EntryPoint:     workload,
					Objective:      "Node-Level Access",
					MaxSeverity:    graph.SeverityCritical,
					AffectsCluster: true,
					RiskScore:      95,
					Steps: []AttackPathStep{
						{
							StepNumber:  1,
							Technique:   TechniqueInitialAccess,
							ToNode:      workload,
							Action:      "Compromise workload",
							Description: fmt.Sprintf("Attacker gains access to %s/%s", workload.Namespace, workload.Name),
							Severity:    graph.SeverityMedium,
							MitreID:     "T1190",
						},
						{
							StepNumber:  2,
							Technique:   TechniquePrivilegeEscalation,
							FromNode:    sa,
							Action:      "Access kubelet API",
							Description: "Use nodes/proxy to directly access kubelet",
							Details:     []string{fmt.Sprintf("Via role: %s", role.Name), "Bypasses RBAC for pod access"},
							Severity:    graph.SeverityCritical,
							ViaRole:     role.Name,
							MitreID:     "T1078.004",
						},
						{
							StepNumber:  3,
							Technique:   TechniqueLateralMovement,
							Action:      "Access all pods on nodes",
							Description: "Read secrets, exec into containers, access pod filesystems",
							Severity:    graph.SeverityCritical,
							MitreID:     "T1021",
						},
					},
					Mitigations: []string{
						"Remove nodes/proxy access",
						"Use pods/exec with proper RBAC instead",
						"Restrict API server access from workloads",
					},
				}
			}

			if path != nil {
				paths = append(paths, path)
				pathID++
			}
		}
	}

	return paths
}

// Helper functions

func hasVerbMatch(verbs, targets []string) bool {
	for _, v := range verbs {
		for _, t := range targets {
			if v == t {
				return true
			}
		}
	}
	return false
}

func updateAttackPathMaxSeverity(r *AttackPathResult, s graph.Severity) {
	if severityValue[s] > severityValue[r.MaxSeverity] {
		r.MaxSeverity = s
	}
}

// AttackPathSummary provides a summary across all analyzed workloads
type AttackPathSummary struct {
	TotalWorkloads          int                 `json:"total_workloads"`
	WorkloadsWithPaths      int                 `json:"workloads_with_paths"`
	TotalPaths              int                 `json:"total_paths"`
	CriticalPaths           int                 `json:"critical_paths"`
	HighPaths               int                 `json:"high_paths"`
	CloudPaths              int                 `json:"cloud_paths"`
	ClusterPaths            int                 `json:"cluster_paths"`
	TopTechniques           []TechniqueCount    `json:"top_techniques"`
	TopObjectives           []ObjectiveCount    `json:"top_objectives"`
	MostVulnerableWorkloads []*AttackPathResult `json:"most_vulnerable_workloads"`
}

// ObjectiveCount tracks attack objectives
type ObjectiveCount struct {
	Objective string `json:"objective"`
	Count     int    `json:"count"`
}

// SummarizeAttackPaths creates a summary from multiple results
func SummarizeAttackPaths(results []*AttackPathResult) *AttackPathSummary {
	summary := &AttackPathSummary{}

	techniqueCounts := make(map[AttackTechnique]int)
	objectiveCounts := make(map[string]int)

	for _, r := range results {
		summary.TotalWorkloads++
		if len(r.Paths) > 0 {
			summary.WorkloadsWithPaths++
		}
		summary.TotalPaths += r.TotalPaths
		summary.CriticalPaths += r.CriticalPaths
		summary.HighPaths += r.HighPaths

		for _, p := range r.Paths {
			if p.AffectsCloud {
				summary.CloudPaths++
			}
			if p.AffectsCluster {
				summary.ClusterPaths++
			}
			objectiveCounts[p.Objective]++

			for _, s := range p.Steps {
				techniqueCounts[s.Technique]++
			}
		}
	}

	// Top techniques
	for tech, count := range techniqueCounts {
		info := TechniqueInfo[tech]
		summary.TopTechniques = append(summary.TopTechniques, TechniqueCount{
			Technique: tech,
			Name:      info.Name,
			Count:     count,
		})
	}
	sort.Slice(summary.TopTechniques, func(i, j int) bool {
		return summary.TopTechniques[i].Count > summary.TopTechniques[j].Count
	})
	if len(summary.TopTechniques) > 5 {
		summary.TopTechniques = summary.TopTechniques[:5]
	}

	// Top objectives
	for obj, count := range objectiveCounts {
		summary.TopObjectives = append(summary.TopObjectives, ObjectiveCount{
			Objective: obj,
			Count:     count,
		})
	}
	sort.Slice(summary.TopObjectives, func(i, j int) bool {
		return summary.TopObjectives[i].Count > summary.TopObjectives[j].Count
	})
	if len(summary.TopObjectives) > 5 {
		summary.TopObjectives = summary.TopObjectives[:5]
	}

	// Most vulnerable workloads (top 5 by path count)
	vulnerable := make([]*AttackPathResult, len(results))
	copy(vulnerable, results)
	sort.Slice(vulnerable, func(i, j int) bool {
		iScore := vulnerable[i].CriticalPaths*100 + vulnerable[i].HighPaths*10 + vulnerable[i].TotalPaths
		jScore := vulnerable[j].CriticalPaths*100 + vulnerable[j].HighPaths*10 + vulnerable[j].TotalPaths
		return iScore > jScore
	})
	if len(vulnerable) > 5 {
		vulnerable = vulnerable[:5]
	}
	summary.MostVulnerableWorkloads = vulnerable

	return summary
}
