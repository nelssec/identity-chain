package analysis

import (
	"fmt"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// ---------------------------------------------------------------------------
// PlatformDetectionResult – identifies the cluster platform and cloud provider
// ---------------------------------------------------------------------------

// DistroProfile contains distro-specific metadata discovered at detection time.
type DistroProfile struct {
	// Platform is a human-readable identifier, e.g. "eks", "gke", "aks", "openshift", "rke2", "k3s", "vanilla".
	Platform string `json:"platform"`
	// CloudProvider is the underlying cloud, e.g. "aws", "gcp", "azure" or "".
	CloudProvider string `json:"cloud_provider,omitempty"`
	// SystemNamespacePrefixes are namespace prefixes that should be treated as system namespaces for this distro.
	SystemNamespacePrefixes []string `json:"system_namespace_prefixes,omitempty"`
	// FeatureFlags captures distro-specific boolean capabilities.
	FeatureFlags map[string]bool `json:"feature_flags,omitempty"`
	// IsManaged is true when the control plane is managed by a cloud provider.
	IsManaged bool `json:"is_managed,omitempty"`
	// IsServerless is true for platforms like Fargate where nodes are ephemeral/invisible.
	IsServerless bool `json:"is_serverless,omitempty"`
	// Features is a human-readable list of detected capabilities.
	Features []string `json:"features,omitempty"`
}

// CloudIdentities summarises cloud IAM identity bindings detected in the graph.
type CloudIdentities struct {
	HasAWSIRSA          bool     `json:"has_aws_irsa"`
	HasAWSPodIdentity   bool     `json:"has_aws_pod_identity"`
	HasGCPWorkloadID    bool     `json:"has_gcp_workload_id"`
	HasAzureWorkloadID  bool     `json:"has_azure_workload_id"`
	HasAzurePodIdentity bool     `json:"has_azure_pod_identity"`
	AWSRoleARNs         []string `json:"aws_role_arns,omitempty"`
	GCPServiceAccounts  []string `json:"gcp_service_accounts,omitempty"`
	AzureClientIDs      []string `json:"azure_client_ids,omitempty"`
}

// PlatformDetectionResult is returned by DetectPlatform.
type PlatformDetectionResult struct {
	Primary        DistroProfile  `json:"primary"`
	CloudIdentities CloudIdentities `json:"cloud_identities"`
}

// DetectPlatform inspects the graph to determine the cluster platform and cloud
// provider. It first checks whether the collector has already embedded a
// DistroProfile on the graph (set during collection), then falls back to
// examining node types and cloud-role annotations.
func DetectPlatform(g *graph.Graph) *PlatformDetectionResult {
	result := &PlatformDetectionResult{
		Primary: DistroProfile{
			Platform:      "vanilla",
			FeatureFlags:  make(map[string]bool),
		},
	}

	// ---- Use pre-computed DistroProfile from collector if available ----------
	if g.DistroProfile != nil && g.DistroProfile.Platform != "" {
		result.Primary.Platform = g.DistroProfile.Platform
		result.Primary.CloudProvider = g.DistroProfile.CloudProvider
		result.Primary.SystemNamespacePrefixes = g.DistroProfile.SystemNSPrefixes
		if g.DistroProfile.FeatureFlags != nil {
			result.Primary.FeatureFlags = g.DistroProfile.FeatureFlags
		}
	}

	// ---- OpenShift detection ------------------------------------------------
	// The OpenShift collector adds SCC / Route / OAuthClient nodes.
	if result.Primary.Platform == "vanilla" {
		if len(g.GetNodesByType(graph.NodeSCC)) > 0 ||
			len(g.GetNodesByType(graph.NodeRoute)) > 0 ||
			len(g.GetNodesByType(graph.NodeOAuthClient)) > 0 {
			result.Primary.Platform = "openshift"
			result.Primary.FeatureFlags["scc"] = true
			result.Primary.SystemNamespacePrefixes = []string{
				"kube-", "openshift-", "default",
			}
		}
	}
	if result.Primary.Platform == "openshift" {
		result.Primary.Features = append(result.Primary.Features, "SCCs", "Routes", "OAuth")
	}

	// ---- Cloud identity scan ------------------------------------------------
	ci := &result.CloudIdentities
	for _, sa := range g.GetNodesByType(graph.NodeServiceAccount) {
		if sa.Metadata.CloudRoleARN != "" {
			if strings.HasPrefix(sa.Metadata.CloudRoleARN, "arn:aws:") {
				ci.HasAWSIRSA = true
				ci.AWSRoleARNs = appendUnique(ci.AWSRoleARNs, sa.Metadata.CloudRoleARN)
			}
		}
		if sa.Metadata.GCPServiceAccount != "" {
			ci.HasGCPWorkloadID = true
			ci.GCPServiceAccounts = appendUnique(ci.GCPServiceAccounts, sa.Metadata.GCPServiceAccount)
		}
		if sa.Metadata.AzureManagedID != "" {
			ci.HasAzureWorkloadID = true
			ci.AzureClientIDs = appendUnique(ci.AzureClientIDs, sa.Metadata.AzureManagedID)
		}
		// EKS Pod Identity stores the association in EKSPodIdentityAssociation metadata (Phase 3 addition).
		if sa.Metadata.EKSPodIdentityAssociation != "" {
			ci.HasAWSPodIdentity = true
		}
	}

	// ---- Derive cloud provider from identities / cloud roles ----------------
	for _, cr := range g.GetNodesByType(graph.NodeCloudRole) {
		switch cr.Metadata.CloudProvider {
		case "aws":
			if result.Primary.CloudProvider == "" {
				result.Primary.CloudProvider = "aws"
			}
		case "gcp":
			if result.Primary.CloudProvider == "" {
				result.Primary.CloudProvider = "gcp"
			}
		case "azure":
			if result.Primary.CloudProvider == "" {
				result.Primary.CloudProvider = "azure"
			}
		}
	}

	// Infer platform from cloud provider when not already set to a named distro.
	if result.Primary.Platform == "vanilla" {
		switch result.Primary.CloudProvider {
		case "aws":
			if ci.HasAWSIRSA || ci.HasAWSPodIdentity {
				result.Primary.Platform = "eks"
				result.Primary.IsManaged = true
				result.Primary.Features = append(result.Primary.Features, "IRSA")
			}
		case "gcp":
			if ci.HasGCPWorkloadID {
				result.Primary.Platform = "gke"
				result.Primary.IsManaged = true
				result.Primary.Features = append(result.Primary.Features, "Workload Identity")
			}
		case "azure":
			if ci.HasAzureWorkloadID || ci.HasAzurePodIdentity {
				result.Primary.Platform = "aks"
				result.Primary.IsManaged = true
				result.Primary.Features = append(result.Primary.Features, "Managed Identity")
			}
		}
	}

	// ---- EKS Pod Identity annotation on SA ----------------------------------
	if result.Primary.Platform == "eks" && ci.HasAWSPodIdentity {
		result.Primary.Features = appendUnique(result.Primary.Features, "Pod Identity")
	}

	return result
}

// ---------------------------------------------------------------------------
// PlatformCheckResult – results of platform-specific security checks
// ---------------------------------------------------------------------------

// PlatformCheckFinding is a single platform security check result.
type PlatformCheckFinding struct {
	CheckID     string         `json:"check_id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    graph.Severity `json:"severity"`
	Passed      bool           `json:"passed"`
	Remediation string         `json:"remediation"`
}

// PlatformCheckResult aggregates all platform-specific check results.
type PlatformCheckResult struct {
	Platform     string                 `json:"platform"`
	TotalChecks  int                    `json:"total_checks"`
	PassedChecks int                    `json:"passed_checks"`
	FailedChecks int                    `json:"failed_checks"`
	Findings     []PlatformCheckFinding `json:"findings"`
}

// RunPlatformChecks executes platform-specific security checks against the graph.
func RunPlatformChecks(g *graph.Graph, p *PlatformDetectionResult) *PlatformCheckResult {
	result := &PlatformCheckResult{
		Platform: "vanilla",
		Findings: []PlatformCheckFinding{},
	}

	if p == nil {
		result.TotalChecks = 0
		return result
	}
	result.Platform = p.Primary.Platform

	var findings []PlatformCheckFinding

	switch p.Primary.Platform {
	case "eks":
		findings = append(findings, runEKSChecks(g, p)...)
	case "gke":
		findings = append(findings, runGKEChecks(g, p)...)
	case "aks":
		findings = append(findings, runAKSChecks(g, p)...)
	case "openshift":
		findings = append(findings, runOpenShiftPlatformChecks(g, p)...)
	}

	// Common checks for all platforms
	findings = append(findings, runCommonChecks(g, p)...)

	for _, f := range findings {
		result.Findings = append(result.Findings, f)
		result.TotalChecks++
		if f.Passed {
			result.PassedChecks++
		} else {
			result.FailedChecks++
		}
	}

	return result
}

func runEKSChecks(g *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	var findings []PlatformCheckFinding

	// Check: IRSA roles should use sts.amazonaws.com audience
	irsaOK := true
	for _, sa := range g.GetNodesByType(graph.NodeServiceAccount) {
		if sa.Metadata.CloudRoleARN != "" && sa.Metadata.TokenAudience != "" {
			if sa.Metadata.TokenAudience != "sts.amazonaws.com" {
				irsaOK = false
				break
			}
		}
	}
	findings = append(findings, PlatformCheckFinding{
		CheckID:     "EKS001",
		Title:       "IRSA token audience",
		Description: "IRSA projected tokens should use sts.amazonaws.com audience",
		Severity:    graph.SeverityMedium,
		Passed:      irsaOK,
		Remediation: "Set serviceAccountToken audience to sts.amazonaws.com in projected volumes",
	})

	// Check: Pod Identity preferred over IRSA where available
	if p.CloudIdentities.HasAWSIRSA && !p.CloudIdentities.HasAWSPodIdentity {
		findings = append(findings, PlatformCheckFinding{
			CheckID:     "EKS002",
			Title:       "EKS Pod Identity not used",
			Description: "EKS Pod Identity provides stronger isolation than IRSA; consider migrating",
			Severity:    graph.SeverityLow,
			Passed:      false,
			Remediation: "Migrate IRSA to EKS Pod Identity for better security posture",
		})
	}

	return findings
}

func runGKEChecks(g *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	var findings []PlatformCheckFinding

	// Check: Workload Identity bindings present
	if p.CloudIdentities.HasGCPWorkloadID {
		findings = append(findings, PlatformCheckFinding{
			CheckID:     "GKE001",
			Title:       "GCP Workload Identity configured",
			Description: "Workload Identity is used for GCP authentication - verify IAM bindings",
			Severity:    graph.SeverityLow,
			Passed:      true,
			Remediation: "Review GCP IAM bindings for each Workload Identity SA",
		})
	}

	return findings
}

func runAKSChecks(g *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	var findings []PlatformCheckFinding

	// Check: Azure Workload Identity preferred over Pod Identity
	if p.CloudIdentities.HasAzurePodIdentity && !p.CloudIdentities.HasAzureWorkloadID {
		findings = append(findings, PlatformCheckFinding{
			CheckID:     "AKS001",
			Title:       "Azure Pod Identity (deprecated) in use",
			Description: "Azure AD Pod Identity is deprecated; migrate to Azure Workload Identity",
			Severity:    graph.SeverityMedium,
			Passed:      false,
			Remediation: "Migrate to Azure Workload Identity (azure.workload.identity/client-id annotation)",
		})
	}

	return findings
}

func runOpenShiftPlatformChecks(g *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	var findings []PlatformCheckFinding

	// Check: Privileged SCC bindings
	sccNodes := g.GetNodesByType(graph.NodeSCC)
	hasPrivilegedSCC := false
	for _, scc := range sccNodes {
		if scc.Metadata.SCCInfo != nil && scc.Metadata.SCCInfo.AllowPrivilegedContainer {
			hasPrivilegedSCC = true
			break
		}
	}

	findings = append(findings, PlatformCheckFinding{
		CheckID:     "OCP001",
		Title:       "Privileged SCC bindings",
		Description: "Privileged SCCs allow containers to bypass security restrictions",
		Severity:    graph.SeverityHigh,
		Passed:      !hasPrivilegedSCC,
		Remediation: "Restrict privileged SCC bindings to only essential system accounts",
	})

	return findings
}

func runCommonChecks(g *graph.Graph, p *PlatformDetectionResult) []PlatformCheckFinding {
	var findings []PlatformCheckFinding

	// Check: default service accounts should not have cloud identities
	defaultWithCloud := 0
	for _, sa := range g.GetNodesByType(graph.NodeServiceAccount) {
		if sa.Name == "default" && sa.HasCloudIdentity() {
			defaultWithCloud++
		}
	}
	findings = append(findings, PlatformCheckFinding{
		CheckID:     "CMN001",
		Title:       "Default ServiceAccount cloud identity",
		Description: "The default ServiceAccount should not have cloud IAM bindings",
		Severity:    graph.SeverityHigh,
		Passed:      defaultWithCloud == 0,
		Remediation: "Remove cloud identity annotations from default ServiceAccounts",
	})

	return findings
}

// ---------------------------------------------------------------------------
// ExploitablePermResult – analysis of dangerously exploitable permissions
// ---------------------------------------------------------------------------

// ExploitableFinding represents a single exploitable permission finding.
type ExploitableFinding struct {
	ID          string         `json:"id"`
	Title       string         `json:"title"`
	Description string         `json:"description"`
	Severity    graph.Severity `json:"severity"`
	Category    string         `json:"category"`
	Remediation string         `json:"remediation"`
	Subject     ExploitableSubject `json:"subject"`
}

// ExploitableSubject is the identity that has the exploitable permission.
type ExploitableSubject struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
}

// ExploitablePermResult is the output of AnalyzeExploitablePermissions.
type ExploitablePermResult struct {
	Findings      []ExploitableFinding `json:"findings"`
	CriticalCount int                  `json:"critical_count"`
	HighCount     int                  `json:"high_count"`
	MediumCount   int                  `json:"medium_count"`
	LowCount      int                  `json:"low_count"`
	Platform      string               `json:"platform"`
}

// AnalyzeExploitablePermissions identifies RBAC permissions that are directly
// exploitable given the detected platform context. It extends the standard
// RBAC audit with platform-aware checks (e.g., IRSA token abuse on EKS).
func AnalyzeExploitablePermissions(g *graph.Graph, p *PlatformDetectionResult) *ExploitablePermResult {
	result := &ExploitablePermResult{
		Findings: []ExploitableFinding{},
	}

	if p != nil {
		result.Platform = p.Primary.Platform
	}

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	id := 0
	nextID := func(prefix string) string {
		id++
		return prefix + strings.ToUpper(result.Platform[:min(3, len(result.Platform))]) + fmt.Sprintf("%03d", id)
	}

	for _, sa := range serviceAccounts {
		roles := collectBoundRoles(g, sa.ID)
		if len(roles) == 0 {
			continue
		}

		// --- cluster-admin / wildcard on all resources -----------------------
		for _, role := range roles {
			for _, rule := range role.Metadata.Rules {
				hasWildcardVerb := containsString(rule.Verbs, "*")
				hasWildcardRes := containsString(rule.Resources, "*")
				if hasWildcardVerb && hasWildcardResource(rule) {
					sev := graph.SeverityCritical
					if !role.Metadata.IsClusterRole {
						sev = graph.SeverityHigh
					}
					finding := ExploitableFinding{
						ID:          nextID("XPLT"),
						Title:       "Wildcard permissions (full control)",
						Description: "ServiceAccount has wildcard resources and verbs - equivalent to cluster-admin",
						Severity:    sev,
						Category:    "over_permissive",
						Remediation: "Replace wildcard permissions with least-privilege explicit rules",
						Subject: ExploitableSubject{
							Kind:      "ServiceAccount",
							Name:      sa.Name,
							Namespace: sa.Namespace,
						},
					}
					result.Findings = append(result.Findings, finding)
				}
				// secrets + get/list/watch = token theft vector
				if containsString(rule.Resources, "secrets") || (hasWildcardRes && hasWildcardVerb) {
					hasRead := containsString(rule.Verbs, "get") || containsString(rule.Verbs, "list") ||
						containsString(rule.Verbs, "watch") || hasWildcardVerb
					if hasRead {
						sev := graph.SeverityCritical
						if !role.Metadata.IsClusterRole {
							sev = graph.SeverityHigh
						}
						result.Findings = append(result.Findings, ExploitableFinding{
							ID:          nextID("XPLT"),
							Title:       "Secrets read access (token theft)",
							Description: "Can read secrets; on K8s <1.24 this allows SA token theft",
							Severity:    sev,
							Category:    "secret_access",
							Remediation: "Restrict secrets access; use bound service account tokens",
							Subject: ExploitableSubject{
								Kind:      "ServiceAccount",
								Name:      sa.Name,
								Namespace: sa.Namespace,
							},
						})
					}
				}
			}
		}

		// --- Platform-specific: EKS IRSA – short-lived token abuse -----------
		if p != nil && p.Primary.Platform == "eks" && sa.Metadata.CloudRoleARN != "" {
			if sa.Metadata.EKSPodIdentityAssociation != "" {
				// Pod Identity – considered lower risk than long-lived IRSA tokens
				result.Findings = append(result.Findings, ExploitableFinding{
					ID:          nextID("XPLT"),
					Title:       "EKS Pod Identity association",
					Description: "SA uses EKS Pod Identity; verify IAM role least-privilege",
					Severity:    graph.SeverityMedium,
					Category:    "cloud_identity",
					Remediation: "Audit IAM role policies attached via EKS Pod Identity",
					Subject: ExploitableSubject{
						Kind:      "ServiceAccount",
						Name:      sa.Name,
						Namespace: sa.Namespace,
					},
				})
			} else {
				result.Findings = append(result.Findings, ExploitableFinding{
					ID:          nextID("XPLT"),
					Title:       "AWS IRSA binding",
					Description: "SA assumes AWS IAM role via IRSA; review IAM policies for over-permission",
					Severity:    graph.SeverityMedium,
					Category:    "cloud_identity",
					Remediation: "Apply least-privilege IAM policies to the assumed role",
					Subject: ExploitableSubject{
						Kind:      "ServiceAccount",
						Name:      sa.Name,
						Namespace: sa.Namespace,
					},
				})
			}
		}
	}

	// Tally severity counts
	for _, f := range result.Findings {
		switch f.Severity {
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

	return result
}

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func hasWildcardResource(rule graph.Rule) bool {
	return containsString(rule.Resources, "*")
}

func appendUnique(slice []string, s string) []string {
	for _, existing := range slice {
		if existing == s {
			return slice
		}
	}
	return append(slice, s)
}

func min(a, b int) int {
	if a < b {
		return a
	}
	return b
}


