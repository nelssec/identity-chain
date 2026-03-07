package analysis

import (
	"fmt"
	"sort"

	"github.com/nelssec/identity-chain/pkg/collector"
	"github.com/nelssec/identity-chain/pkg/graph"
)

// ---------------------------------------------------------------------------
// IdentityRisk – comprehensive risk scoring for Kubernetes identities
// ---------------------------------------------------------------------------

// IdentityRiskOptions configures the risk calculation.
type IdentityRiskOptions struct {
	Namespace     string
	IncludeSystem bool
	MinScore      int
	TopN          int
}

// IdentityRiskFactor is a single contributor to an identity's risk score.
type IdentityRiskFactor struct {
	Severity    graph.Severity `json:"severity"`
	Description string         `json:"description"`
	Score       int            `json:"score"`
}

// IdentityRiskEntry is the risk report for a single identity.
type IdentityRiskEntry struct {
	Name             string               `json:"name"`
	Namespace        string               `json:"namespace"`
	Kind             string               `json:"kind"`
	RiskScore        int                  `json:"risk_score"`
	RiskLevel        string               `json:"risk_level"`
	HasCloudAccess   bool                 `json:"has_cloud_access"`
	HasClusterAdmin  bool                 `json:"has_cluster_admin"`
	HasSecretsAccess bool                 `json:"has_secrets_access"`
	IsUnused         bool                 `json:"is_unused"`
	WorkloadCount    int                  `json:"workload_count"`
	RiskFactors      []IdentityRiskFactor `json:"risk_factors"`
	Recommendations  []string             `json:"recommendations"`
}

// IdentityRiskSummary holds aggregate statistics.
type IdentityRiskSummary struct {
	TotalIdentities     int    `json:"total_identities"`
	CriticalRiskCount   int    `json:"critical_risk_count"`
	HighRiskCount       int    `json:"high_risk_count"`
	MediumRiskCount     int    `json:"medium_risk_count"`
	LowRiskCount        int    `json:"low_risk_count"`
	WithCloudAccess     int    `json:"with_cloud_access"`
	WithClusterAdmin    int    `json:"with_cluster_admin"`
	WithSecretsAccess   int    `json:"with_secrets_access"`
	OverprivilegedCount int    `json:"overprivileged_count"`
	AverageScore        int    `json:"average_score"`
}

// IdentityRiskResult is the output of CalculateIdentityRisk.
type IdentityRiskResult struct {
	TopRisks        []IdentityRiskEntry  `json:"top_risks"`
	AllRisks        []IdentityRiskEntry  `json:"all_risks,omitempty"`
	Summary         IdentityRiskSummary  `json:"summary"`
	Recommendations []string             `json:"recommendations"`
}

// CalculateIdentityRisk computes a risk score for every service account in the
// graph and returns the top-N riskiest identities.
func CalculateIdentityRisk(g *graph.Graph, opts IdentityRiskOptions) *IdentityRiskResult {
	result := &IdentityRiskResult{
		TopRisks:        []IdentityRiskEntry{},
		AllRisks:        []IdentityRiskEntry{},
		Recommendations: []string{},
	}

	if opts.TopN == 0 {
		opts.TopN = 10
	}

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)

	for _, sa := range serviceAccounts {
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}

		entry := scoreIdentity(g, sa)

		if opts.MinScore > 0 && entry.RiskScore < opts.MinScore {
			continue
		}

		result.AllRisks = append(result.AllRisks, entry)
		result.Summary.TotalIdentities++

		switch entry.RiskLevel {
		case "critical":
			result.Summary.CriticalRiskCount++
		case "high":
			result.Summary.HighRiskCount++
		case "medium":
			result.Summary.MediumRiskCount++
		case "low":
			result.Summary.LowRiskCount++
		}

		if entry.HasCloudAccess {
			result.Summary.WithCloudAccess++
		}
		if entry.HasClusterAdmin {
			result.Summary.WithClusterAdmin++
		}
		if entry.HasSecretsAccess {
			result.Summary.WithSecretsAccess++
		}
		if entry.RiskScore > 60 && entry.IsUnused {
			result.Summary.OverprivilegedCount++
		}
	}

	// Sort by risk score descending
	sort.Slice(result.AllRisks, func(i, j int) bool {
		return result.AllRisks[i].RiskScore > result.AllRisks[j].RiskScore
	})

	// Compute average score
	if result.Summary.TotalIdentities > 0 {
		total := 0
		for _, e := range result.AllRisks {
			total += e.RiskScore
		}
		result.Summary.AverageScore = total / result.Summary.TotalIdentities
	}

	// Top-N
	n := opts.TopN
	if n > len(result.AllRisks) {
		n = len(result.AllRisks)
	}
	result.TopRisks = result.AllRisks[:n]

	generateIdentityRiskRecommendations(result)

	return result
}

func scoreIdentity(g *graph.Graph, sa *graph.Node) IdentityRiskEntry {
	entry := IdentityRiskEntry{
		Name:      sa.Name,
		Namespace: sa.Namespace,
		Kind:      "ServiceAccount",
	}

	workloads := g.GetWorkloadsUsingSA(sa.ID)
	entry.WorkloadCount = len(workloads)
	entry.IsUnused = len(workloads) == 0

	roles := collectBoundRoles(g, sa.ID)

	for _, role := range roles {
		for _, rule := range role.Metadata.Rules {
			hasWildcardVerb := containsString(rule.Verbs, "*")
			hasWildcardRes := containsString(rule.Resources, "*")

			// cluster-admin equivalent
			if hasWildcardVerb && hasWildcardRes && role.Metadata.IsClusterRole {
				entry.HasClusterAdmin = true
				entry.RiskFactors = append(entry.RiskFactors, IdentityRiskFactor{
					Severity:    graph.SeverityCritical,
					Description: "Has cluster-admin equivalent via " + role.Name,
					Score:       50,
				})
			}

			// Secrets access
			if containsString(rule.Resources, "secrets") || (hasWildcardRes) {
				if containsString(rule.Verbs, "get") || containsString(rule.Verbs, "list") || hasWildcardVerb {
					entry.HasSecretsAccess = true
					sev := graph.SeverityCritical
					score := 30
					if !role.Metadata.IsClusterRole {
						sev = graph.SeverityHigh
						score = 15
					}
					entry.RiskFactors = append(entry.RiskFactors, IdentityRiskFactor{
						Severity:    sev,
						Description: "Can read secrets via " + role.Name,
						Score:       score,
					})
				}
			}

			// Workload creation
			for _, res := range rule.Resources {
				if res == "pods" || res == "deployments" || res == "daemonsets" || res == "statefulsets" {
					if containsString(rule.Verbs, "create") || hasWildcardVerb {
						entry.RiskFactors = append(entry.RiskFactors, IdentityRiskFactor{
							Severity:    graph.SeverityHigh,
							Description: "Can create " + res + " via " + role.Name,
							Score:       15,
						})
					}
				}
			}

			// Dangerous verbs
			for _, verb := range rule.Verbs {
				switch verb {
				case "impersonate":
					entry.RiskFactors = append(entry.RiskFactors, IdentityRiskFactor{
						Severity:    graph.SeverityCritical,
						Description: "Has impersonate verb via " + role.Name,
						Score:       40,
					})
				case "bind":
					entry.RiskFactors = append(entry.RiskFactors, IdentityRiskFactor{
						Severity:    graph.SeverityCritical,
						Description: "Has bind verb via " + role.Name,
						Score:       40,
					})
				case "escalate":
					entry.RiskFactors = append(entry.RiskFactors, IdentityRiskFactor{
						Severity:    graph.SeverityCritical,
						Description: "Has escalate verb via " + role.Name,
						Score:       40,
					})
				}
			}
		}
	}

	// Cloud identity risk
	if sa.Metadata.CloudRoleARN != "" || sa.Metadata.GCPServiceAccount != "" || sa.Metadata.AzureManagedID != "" {
		entry.HasCloudAccess = true
		entry.RiskFactors = append(entry.RiskFactors, IdentityRiskFactor{
			Severity:    graph.SeverityHigh,
			Description: "Has cloud IAM identity binding",
			Score:       20,
		})
	}

	// Unused with permissions penalty
	if entry.IsUnused && len(roles) > 0 {
		entry.RiskFactors = append(entry.RiskFactors, IdentityRiskFactor{
			Severity:    graph.SeverityMedium,
			Description: "Has permissions but no workloads attached (orphaned)",
			Score:       10,
		})
	}

	// Compute total score
	for _, f := range entry.RiskFactors {
		entry.RiskScore += f.Score
	}
	if entry.RiskScore > 100 {
		entry.RiskScore = 100
	}

	// Determine risk level
	switch {
	case entry.RiskScore >= 70 || entry.HasClusterAdmin:
		entry.RiskLevel = "critical"
	case entry.RiskScore >= 40:
		entry.RiskLevel = "high"
	case entry.RiskScore >= 20:
		entry.RiskLevel = "medium"
	default:
		entry.RiskLevel = "low"
	}

	// Per-identity recommendations
	if entry.HasClusterAdmin {
		entry.Recommendations = append(entry.Recommendations, "Replace cluster-admin binding with least-privilege roles")
	}
	if entry.HasSecretsAccess && entry.IsUnused {
		entry.Recommendations = append(entry.Recommendations, "Remove secrets access from unused service account")
	}
	if entry.IsUnused && len(roles) > 0 {
		entry.Recommendations = append(entry.Recommendations, "Remove or deactivate this orphaned service account")
	}

	return entry
}

func generateIdentityRiskRecommendations(result *IdentityRiskResult) {
	if result.Summary.WithClusterAdmin > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("%d identities have cluster-admin equivalent access - review urgently", result.Summary.WithClusterAdmin))
	}
	if result.Summary.WithSecretsAccess > 5 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("%d identities can read secrets - restrict with resourceNames", result.Summary.WithSecretsAccess))
	}
	if result.Summary.OverprivilegedCount > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("%d identities are over-privileged and unused - consider removing", result.Summary.OverprivilegedCount))
	}
	if result.Summary.WithCloudAccess > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Audit %d cloud IAM bindings for least-privilege compliance", result.Summary.WithCloudAccess))
	}
}
