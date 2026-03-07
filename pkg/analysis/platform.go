package analysis

import (
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// ────────────────────────────────────────────────────────────────────────────
// Result types used by DetectPlatform / RunPlatformChecks /
// AnalyzeExploitablePermissions.  These are referenced in compliance.go,
// cmd/idc/main.go and pkg/api/server.go.
// ────────────────────────────────────────────────────────────────────────────

// PlatformProfile holds detected information about a single platform layer.
type PlatformProfile struct {
	Platform     string   `json:"platform"`
	CloudProvider string  `json:"cloud_provider"`
	IsManaged    bool     `json:"is_managed"`
	IsServerless bool     `json:"is_serverless"`
	Features     []string `json:"features,omitempty"`
}

// CloudIdentityInfo summarises which cloud identity mechanisms are in use.
type CloudIdentityInfo struct {
	HasAWSIRSA         bool     `json:"has_aws_irsa"`
	HasAWSPodIdentity  bool     `json:"has_aws_pod_identity"`
	HasGCPWorkloadID   bool     `json:"has_gcp_workload_id"`
	HasAzureWorkloadID bool     `json:"has_azure_workload_id"`
	HasAzurePodIdentity bool    `json:"has_azure_pod_identity"`
	AWSRoleARNs        []string `json:"aws_role_arns,omitempty"`
	GCPServiceAccounts []string `json:"gcp_service_accounts,omitempty"`
	AzureClientIDs     []string `json:"azure_client_ids,omitempty"`
}

// PlatformDetectionResult is the top-level return value of DetectPlatform.
type PlatformDetectionResult struct {
	Primary        PlatformProfile   `json:"primary"`
	CloudIdentities CloudIdentityInfo `json:"cloud_identities"`
	// DistroProfile holds the richer distro metadata when detection has run.
	DistroProfile  *DistroProfile    `json:"distro_profile,omitempty"`
}

// PlatformCheckFinding is a single result from a platform-specific security check.
type PlatformCheckFinding struct {
	CheckID     string         `json:"check_id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    graph.Severity `json:"severity"`
	Passed      bool           `json:"passed"`
	Remediation string         `json:"remediation,omitempty"`
}

// PlatformCheckResult is the return value of RunPlatformChecks.
type PlatformCheckResult struct {
	Platform     string                 `json:"platform"`
	TotalChecks  int                    `json:"total_checks"`
	PassedChecks int                    `json:"passed_checks"`
	FailedChecks int                    `json:"failed_checks"`
	Findings     []PlatformCheckFinding `json:"findings"`
}

// ExploitablePermSubject identifies the subject of an exploitable permission finding.
type ExploitablePermSubject struct {
	Namespace string `json:"namespace"`
	Name      string `json:"name"`
	Kind      string `json:"kind"`
}

// ExploitablePermFinding describes one exploitable permission combination.
type ExploitablePermFinding struct {
	ID          string                 `json:"id,omitempty"`
	Identity    string                 `json:"identity"`
	Namespace   string                 `json:"namespace"`
	Subject     ExploitablePermSubject `json:"subject"`
	Category    string                 `json:"category"`
	Title       string                 `json:"title"`
	Description string                 `json:"description"`
	Severity    graph.Severity         `json:"severity"`
	Remediation string                 `json:"remediation,omitempty"`
}

// ExploitablePermResult is the return value of AnalyzeExploitablePermissions.
type ExploitablePermResult struct {
	Findings      []ExploitablePermFinding `json:"findings"`
	CriticalCount int                      `json:"critical_count"`
	HighCount     int                      `json:"high_count"`
	MediumCount   int                      `json:"medium_count"`
	LowCount      int                      `json:"low_count"`
}

// ────────────────────────────────────────────────────────────────────────────
// DetectPlatform inspects the graph to determine the Kubernetes distribution,
// cloud provider, and cloud identity mechanisms in use.
// ────────────────────────────────────────────────────────────────────────────

func DetectPlatform(g *graph.Graph) *PlatformDetectionResult {
	result := &PlatformDetectionResult{
		Primary: PlatformProfile{
			Platform:      "kubernetes",
			CloudProvider: "unknown",
		},
	}

	// If the graph carries a pre-computed DistroProfile, prefer it.
	if g.Metadata != nil {
		if dp, ok := g.Metadata["distro_profile"].(*DistroProfile); ok && dp != nil {
			result.DistroProfile = dp
			result.Primary.Platform = dp.Platform
			result.Primary.CloudProvider = dp.CloudProvider
			result.Primary.IsManaged = isManaged(dp.Platform)
			result.Primary.IsServerless = isServerless(dp.Platform)
		}
	}

	// Heuristic detection from node labels when DistroProfile is absent.
	if result.DistroProfile == nil {
		result.Primary.Platform, result.Primary.CloudProvider = heuristicDetect(g)
		result.Primary.IsManaged = isManaged(result.Primary.Platform)
		result.Primary.IsServerless = isServerless(result.Primary.Platform)
	}

	// Scan service-account cloud annotations.
	ci := &result.CloudIdentities
	seenARNs := map[string]bool{}
	seenGCP := map[string]bool{}
	seenAzure := map[string]bool{}

	for _, sa := range g.GetNodesByType(graph.NodeServiceAccount) {
		if sa.Metadata.CloudRoleARN != "" && !seenARNs[sa.Metadata.CloudRoleARN] {
			ci.HasAWSIRSA = true
			ci.AWSRoleARNs = append(ci.AWSRoleARNs, sa.Metadata.CloudRoleARN)
			seenARNs[sa.Metadata.CloudRoleARN] = true
		}
		if sa.Metadata.GCPServiceAccount != "" && !seenGCP[sa.Metadata.GCPServiceAccount] {
			ci.HasGCPWorkloadID = true
			ci.GCPServiceAccounts = append(ci.GCPServiceAccounts, sa.Metadata.GCPServiceAccount)
			seenGCP[sa.Metadata.GCPServiceAccount] = true
		}
		if sa.Metadata.AzureManagedID != "" && !seenAzure[sa.Metadata.AzureManagedID] {
			ci.HasAzureWorkloadID = true
			ci.AzureClientIDs = append(ci.AzureClientIDs, sa.Metadata.AzureManagedID)
			seenAzure[sa.Metadata.AzureManagedID] = true
		}
		// EKS Pod Identity is detected by a separate annotation.
		if sa.Annotations != nil {
			if _, ok := sa.Annotations["pods.eks.amazonaws.com/service-account-token-audience"]; ok {
				ci.HasAWSPodIdentity = true
			}
		}
	}

	// Detect Azure Pod Identity via node labels.
	for _, workload := range g.GetNodesByType(graph.NodeWorkload) {
		if workload.Annotations != nil {
			if _, ok := workload.Annotations["aadpodidbinding"]; ok {
				ci.HasAzurePodIdentity = true
			}
		}
	}

	return result
}

// heuristicDetect tries to infer platform/cloud from node labels.
func heuristicDetect(g *graph.Graph) (platform, cloudProvider string) {
	platform = "kubernetes"
	cloudProvider = "unknown"

	// Check for OpenShift SCCs.
	if len(g.GetNodesByType(graph.NodeSCC)) > 0 {
		platform = "openshift"
		return
	}

	// Look at workload / SA annotations for cloud-provider hints.
	for _, sa := range g.GetNodesByType(graph.NodeServiceAccount) {
		if sa.Metadata.CloudRoleARN != "" {
			cloudProvider = "aws"
		} else if sa.Metadata.GCPServiceAccount != "" {
			cloudProvider = "gcp"
		} else if sa.Metadata.AzureManagedID != "" {
			cloudProvider = "azure"
		}
	}

	// Infer managed-service platform from cloud provider + common naming.
	switch cloudProvider {
	case "aws":
		platform = "eks"
	case "gcp":
		platform = "gke"
	case "azure":
		platform = "aks"
	}

	return
}

func isManaged(platform string) bool {
	switch strings.ToLower(platform) {
	case "eks", "gke", "aks":
		return true
	}
	return false
}

func isServerless(platform string) bool {
	switch strings.ToLower(platform) {
	case "fargate", "cloud-run":
		return true
	}
	return false
}

// ────────────────────────────────────────────────────────────────────────────
// RunPlatformChecks executes platform-specific security checks.
// ────────────────────────────────────────────────────────────────────────────

func RunPlatformChecks(g *graph.Graph, p *PlatformDetectionResult) *PlatformCheckResult {
	result := &PlatformCheckResult{
		Platform: p.Primary.Platform,
		Findings: []PlatformCheckFinding{},
	}

	var findings []PlatformCheckFinding

	switch strings.ToLower(p.Primary.Platform) {
	case "openshift":
		findings = append(findings, runOpenShiftChecks(g)...)
	case "eks":
		findings = append(findings, runEKSChecks(g, p)...)
	case "gke":
		findings = append(findings, runGKEChecks(g, p)...)
	case "aks":
		findings = append(findings, runAKSChecks(g, p)...)
	default:
		findings = append(findings, runGenericChecks(g)...)
	}

	result.Findings = findings
	result.TotalChecks = len(findings)
	for _, f := range findings {
		if f.Passed {
			result.PassedChecks++
		} else {
			result.FailedChecks++
		}
	}

	return result
}

func runGenericChecks(g *graph.Graph) []PlatformCheckFinding {
	var findings []PlatformCheckFinding

	// Check: no wildcard cluster roles bound to service accounts.
	wildcardRoles := 0
	for _, role := range g.GetNodesByType(graph.NodeRole) {
		if !role.Metadata.IsClusterRole {
			continue
		}
		for _, rule := range role.Metadata.Rules {
			for _, v := range rule.Verbs {
				if v == "*" {
					wildcardRoles++
					break
				}
			}
		}
	}
	findings = append(findings, PlatformCheckFinding{
		CheckID:     "PLT001",
		Title:       "No wildcard ClusterRoles",
		Description: "ClusterRoles with wildcard verbs grant unrestricted API access",
		Severity:    graph.SeverityCritical,
		Passed:      wildcardRoles == 0,
		Remediation: "Remove wildcard verbs from ClusterRoles and use least-privilege rules",
	})

	return findings
}

func runOpenShiftChecks(g *graph.Graph) []PlatformCheckFinding {
	base := runGenericChecks(g)

	// Wire into existing SCC analysis.
	sccResult := AnalyzeSCCs(g)
	riskyBindings := len(sccResult.RiskyBindings)
	base = append(base, PlatformCheckFinding{
		CheckID:     "OCP001",
		Title:       "No risky SCC bindings",
		Description: "Service accounts bound to privileged SCCs can escalate to root",
		Severity:    graph.SeverityHigh,
		Passed:      riskyBindings == 0,
		Remediation: "Restrict privileged SCC usage to dedicated system service accounts",
	})

	return base
}

func runEKSChecks(g *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	base := runGenericChecks(g)

	// Check: IRSA roles use condition keys.
	irsaFindings := checkIRSAConditions(g, p)
	base = append(base, irsaFindings...)

	return base
}

func checkIRSAConditions(_ *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	// Placeholder: in a full implementation we would parse the IAM trust policy
	// stored on CloudRole nodes to verify sub/aud conditions.
	hasIRSA := p.CloudIdentities.HasAWSIRSA
	return []PlatformCheckFinding{
		{
			CheckID:     "EKS001",
			Title:       "IRSA roles scoped with OIDC conditions",
			Description: "IRSA IAM roles should use aws:SourceAccount and OIDC sub conditions",
			Severity:    graph.SeverityHigh,
			Passed:      !hasIRSA, // conservatively flag if IRSA is in use (can't verify conditions without live IAM data)
			Remediation: "Add oidc.eks.<region>.amazonaws.com/id/<hash>:sub condition to trust policy",
		},
	}
}

func runGKEChecks(g *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	base := runGenericChecks(g)

	hasWI := p.CloudIdentities.HasGCPWorkloadID
	base = append(base, PlatformCheckFinding{
		CheckID:     "GKE001",
		Title:       "Workload Identity configured",
		Description: "GKE Workload Identity should be used instead of node service accounts",
		Severity:    graph.SeverityMedium,
		Passed:      hasWI,
		Remediation: "Enable Workload Identity and annotate Kubernetes service accounts with GCP SA emails",
	})

	return base
}

func runAKSChecks(g *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	base := runGenericChecks(g)

	hasWI := p.CloudIdentities.HasAzureWorkloadID
	base = append(base, PlatformCheckFinding{
		CheckID:     "AKS001",
		Title:       "Azure Workload Identity configured",
		Description: "AKS workloads should use Azure Workload Identity instead of pod identity",
		Severity:    graph.SeverityMedium,
		Passed:      hasWI,
		Remediation: "Migrate from AAD Pod Identity to Azure Workload Identity",
	})

	return base
}

// ────────────────────────────────────────────────────────────────────────────
// AnalyzeExploitablePermissions identifies identity→permission combinations
// that an attacker could directly exploit.
// ────────────────────────────────────────────────────────────────────────────

func AnalyzeExploitablePermissions(g *graph.Graph, p *PlatformDetectionResult) *ExploitablePermResult {
	result := &ExploitablePermResult{
		Findings: []ExploitablePermFinding{},
	}

	// Delegate to existing cloud-IAM analysis for cloud-related findings.
	cloudResult := AnalyzeCloudIAM(g)
	for _, cf := range cloudResult.Findings {
		f := ExploitablePermFinding{
			Identity:    cf.RoleARN,
			Subject:     ExploitablePermSubject{Name: cf.RoleARN, Kind: "CloudRole"},
			Category:    "cloud_iam",
			Title:       cf.Title,
			Description: cf.Description,
			Severity:    cf.Severity,
			Remediation: cf.Remediation,
		}
		result.Findings = append(result.Findings, f)
		countSeverity(result, cf.Severity)
	}

	// Scan RBAC for directly exploitable permission sets.
	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			for _, rule := range role.Metadata.Rules {
				finding := classifyExploitableRule(sa, role, rule)
				if finding == nil {
					continue
				}
				result.Findings = append(result.Findings, *finding)
				countSeverity(result, finding.Severity)
			}
		}
	}

	// Platform-specific: IRSA permissions on EKS.
	if strings.EqualFold(p.Primary.Platform, "eks") {
		for _, sa := range serviceAccounts {
			if sa.Metadata.CloudRoleARN == "" {
				continue
			}
			irsaFindings := analyzeIRSAPermissions(g, sa)
			result.Findings = append(result.Findings, irsaFindings...)
			for _, f := range irsaFindings {
				countSeverity(result, f.Severity)
			}
		}
	}

	return result
}

func countSeverity(result *ExploitablePermResult, sev graph.Severity) {
	switch sev {
	case graph.SeverityCritical:
		result.CriticalCount++
	case graph.SeverityHigh:
		result.HighCount++
	case graph.SeverityMedium:
		result.MediumCount++
	case graph.SeverityLow:
		result.LowCount++
	}
}

func classifyExploitableRule(sa, role *graph.Node, rule graph.Rule) *ExploitablePermFinding {
	hasWildcardVerb := false
	hasDangerousVerb := false
	for _, v := range rule.Verbs {
		if v == "*" {
			hasWildcardVerb = true
		}
		if v == "create" || v == "update" || v == "patch" || v == "delete" {
			hasDangerousVerb = true
		}
	}

	subject := ExploitablePermSubject{
		Namespace: sa.Namespace,
		Name:      sa.Name,
		Kind:      "ServiceAccount",
	}

	for _, res := range rule.Resources {
		switch res {
		case "*":
			if hasWildcardVerb {
				return &ExploitablePermFinding{
					Identity:    sa.Name,
					Namespace:   sa.Namespace,
					Subject:     subject,
					Category:    "over_permissive",
					Title:       "Full cluster access via wildcard rule",
					Description: "Service account has *.* permission via role " + role.Name,
					Severity:    graph.SeverityCritical,
					Remediation: "Replace wildcard rules with explicit, least-privilege rules",
				}
			}
		case "secrets":
			if hasWildcardVerb || containsString(rule.Verbs, "get") || containsString(rule.Verbs, "list") {
				sev := graph.SeverityCritical
				if !role.Metadata.IsClusterRole {
					sev = graph.SeverityHigh
				}
				return &ExploitablePermFinding{
					Identity:    sa.Name,
					Namespace:   sa.Namespace,
					Subject:     subject,
					Category:    "secret_access",
					Title:       "Secrets read access",
					Description: "Service account can read secrets via role " + role.Name,
					Severity:    sev,
					Remediation: "Remove secret read permissions unless strictly required",
				}
			}
		case "pods/exec":
			if hasWildcardVerb || hasDangerousVerb || containsString(rule.Verbs, "get") {
				return &ExploitablePermFinding{
					Identity:    sa.Name,
					Namespace:   sa.Namespace,
					Subject:     subject,
					Category:    "privilege_escalation",
					Title:       "Pod exec access",
					Description: "Service account can exec into pods via role " + role.Name,
					Severity:    graph.SeverityHigh,
					Remediation: "Remove pods/exec permissions unless strictly required",
				}
			}
		}
	}
	return nil
}

func analyzeIRSAPermissions(g *graph.Graph, sa *graph.Node) []ExploitablePermFinding {
	var findings []ExploitablePermFinding

	subject := ExploitablePermSubject{
		Namespace: sa.Namespace,
		Name:      sa.Name,
		Kind:      "ServiceAccount",
	}

	for _, edge := range g.GetOutEdges(sa.ID) {
		if edge.Type != graph.EdgeAssumes {
			continue
		}
		cloudRole := g.GetNode(edge.To)
		if cloudRole == nil {
			continue
		}
		for _, policy := range cloudRole.Metadata.CloudPolicies {
			if policy.IsAdmin {
				findings = append(findings, ExploitablePermFinding{
					Identity:    sa.Name,
					Namespace:   sa.Namespace,
					Subject:     subject,
					Category:    "cloud_iam",
					Title:       "IRSA role with admin cloud permissions",
					Description: "Service account assumes IAM role " + cloudRole.Name + " which has admin privileges",
					Severity:    graph.SeverityCritical,
					Remediation: "Scope IRSA role policies to minimum required AWS actions and resources",
				})
			}
		}
	}

	return findings
}

// ────────────────────────────────────────────────────────────────────────────
// DistroProfile – referenced by the distro detector package and stored on the
// graph metadata so that DetectPlatform can consume it.
// ────────────────────────────────────────────────────────────────────────────

// DistroProfile captures per-distro configuration used by analysis.
type DistroProfile struct {
	Platform                string            `json:"platform"`
	CloudProvider           string            `json:"cloud_provider"`
	SystemNamespacePrefixes []string          `json:"system_namespace_prefixes"`
	FeatureFlags            map[string]bool   `json:"feature_flags"`
}

// DefaultSystemNamespacePrefixes returns the baseline list of system namespace
// prefixes that all distributions share.
func DefaultSystemNamespacePrefixes() []string {
	return []string{"kube-", "kube-system", "kube-public", "kube-node-lease"}
}
