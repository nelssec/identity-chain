package analysis

import (
	"sort"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

// IdentityRiskOptions configures the identity risk calculation.
type IdentityRiskOptions struct {
	IncludeSystem bool
	Namespace     string
	MinScore      int
	TopN          int
}

// IdentityRiskFactor is a single contributor to an identity's risk score.
// (Named distinctly from blast.go's RiskFactor to avoid redeclaration.)
type IdentityRiskFactor struct {
	Description string         `json:"description"`
	Severity    graph.Severity `json:"severity"`
	Score       int            `json:"score"`
}

// IdentityRisk holds the risk assessment for a single identity.
type IdentityRisk struct {
	Name        string               `json:"name"`
	Namespace   string               `json:"namespace"`
	Kind        string               `json:"kind"`
	RiskScore   int                  `json:"risk_score"`
	RiskLevel   string               `json:"risk_level"`
	RiskFactors []IdentityRiskFactor `json:"risk_factors,omitempty"`
}

// IdentityRiskSummary aggregates statistics across all identities.
type IdentityRiskSummary struct {
	TotalIdentities     int `json:"total_identities"`
	CriticalRiskCount   int `json:"critical_risk_count"`
	HighRiskCount       int `json:"high_risk_count"`
	MediumRiskCount     int `json:"medium_risk_count"`
	LowRiskCount        int `json:"low_risk_count"`
	WithCloudAccess     int `json:"with_cloud_access"`
	WithClusterAdmin    int `json:"with_cluster_admin"`
	WithSecretsAccess   int `json:"with_secrets_access"`
	OverprivilegedCount int `json:"overprivileged_count"`
	AverageScore        int `json:"average_score"`
}

// IdentityRiskResult is the top-level return value of CalculateIdentityRisk.
type IdentityRiskResult struct {
	TopRisks        []IdentityRisk      `json:"top_risks"`
	Summary         IdentityRiskSummary `json:"summary"`
	Recommendations []string            `json:"recommendations,omitempty"`
}

// ────────────────────────────────────────────────────────────────────────────
// CalculateIdentityRisk assesses risk for all service accounts in the graph.
// ────────────────────────────────────────────────────────────────────────────

func CalculateIdentityRisk(g *graph.Graph, opts IdentityRiskOptions) *IdentityRiskResult {
	if opts.TopN == 0 {
		opts.TopN = 20
	}

	result := &IdentityRiskResult{
		TopRisks: []IdentityRisk{},
	}

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	var allRisks []IdentityRisk
	totalScore := 0

	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && isSystemNamespace(sa.Namespace) {
			continue
		}
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}

		risk := assessIdentityRisk(g, sa)
		result.Summary.TotalIdentities++

		if risk.RiskScore >= opts.MinScore {
			allRisks = append(allRisks, risk)
		}

		totalScore += risk.RiskScore

		// Update summary buckets.
		switch risk.RiskLevel {
		case "critical":
			result.Summary.CriticalRiskCount++
		case "high":
			result.Summary.HighRiskCount++
		case "medium":
			result.Summary.MediumRiskCount++
		default:
			result.Summary.LowRiskCount++
		}

		// Cloud / admin / secrets counters.
		if sa.Metadata.CloudRoleARN != "" || sa.Metadata.GCPServiceAccount != "" || sa.Metadata.AzureManagedID != "" {
			result.Summary.WithCloudAccess++
		}

		roles := collectBoundRoles(g, sa.ID)
		if isBoundToClusterAdmin(roles) {
			result.Summary.WithClusterAdmin++
		}
		if canReadAllSecrets(g, roles) {
			result.Summary.WithSecretsAccess++
		}
		if len(roles) > 3 {
			result.Summary.OverprivilegedCount++
		}
	}

	if result.Summary.TotalIdentities > 0 {
		result.Summary.AverageScore = totalScore / result.Summary.TotalIdentities
	}

	// Sort by score descending.
	sort.Slice(allRisks, func(i, j int) bool {
		return allRisks[i].RiskScore > allRisks[j].RiskScore
	})

	// Return top N.
	limit := opts.TopN
	if limit > len(allRisks) {
		limit = len(allRisks)
	}
	result.TopRisks = allRisks[:limit]

	// Generate high-level recommendations.
	result.Recommendations = generateRiskRecommendations(result)

	return result
}

func assessIdentityRisk(g *graph.Graph, sa *graph.Node) IdentityRisk {
	risk := IdentityRisk{
		Name:      sa.Name,
		Namespace: sa.Namespace,
		Kind:      "ServiceAccount",
	}

	roles := collectBoundRoles(g, sa.ID)

	// Cloud identity bonus.
	if sa.Metadata.CloudRoleARN != "" {
		risk.RiskFactors = append(risk.RiskFactors, IdentityRiskFactor{
			Description: "Has AWS IRSA cloud role: " + sa.Metadata.CloudRoleARN,
			Severity:    graph.SeverityHigh,
			Score:       20,
		})
		risk.RiskScore += 20
	}
	if sa.Metadata.GCPServiceAccount != "" {
		risk.RiskFactors = append(risk.RiskFactors, IdentityRiskFactor{
			Description: "Has GCP Workload Identity: " + sa.Metadata.GCPServiceAccount,
			Severity:    graph.SeverityHigh,
			Score:       20,
		})
		risk.RiskScore += 20
	}
	if sa.Metadata.AzureManagedID != "" {
		risk.RiskFactors = append(risk.RiskFactors, IdentityRiskFactor{
			Description: "Has Azure Managed Identity: " + sa.Metadata.AzureManagedID,
			Severity:    graph.SeverityHigh,
			Score:       20,
		})
		risk.RiskScore += 20
	}

	// Cluster-admin check.
	if isBoundToClusterAdmin(roles) {
		risk.RiskFactors = append(risk.RiskFactors, IdentityRiskFactor{
			Description: "Bound to cluster-admin role",
			Severity:    graph.SeverityCritical,
			Score:       50,
		})
		risk.RiskScore += 50
	}

	// Secrets access.
	if canReadAllSecrets(g, roles) {
		risk.RiskFactors = append(risk.RiskFactors, IdentityRiskFactor{
			Description: "Can read cluster-wide secrets",
			Severity:    graph.SeverityCritical,
			Score:       40,
		})
		risk.RiskScore += 40
	}

	// Wildcard permissions.
	for _, role := range roles {
		for _, rule := range role.Metadata.Rules {
			for _, v := range rule.Verbs {
				if v == "*" {
					risk.RiskFactors = append(risk.RiskFactors, IdentityRiskFactor{
						Description: "Has wildcard permissions via role " + role.Name,
						Severity:    graph.SeverityCritical,
						Score:       35,
					})
					risk.RiskScore += 35
					goto doneWildcard
				}
			}
		}
	}
doneWildcard:

	// Automount token.
	if sa.Metadata.AutomountToken {
		risk.RiskFactors = append(risk.RiskFactors, IdentityRiskFactor{
			Description: "Service account token is auto-mounted",
			Severity:    graph.SeverityLow,
			Score:       5,
		})
		risk.RiskScore += 5
	}

	// Determine level.
	switch {
	case risk.RiskScore >= 70:
		risk.RiskLevel = "critical"
	case risk.RiskScore >= 40:
		risk.RiskLevel = "high"
	case risk.RiskScore >= 20:
		risk.RiskLevel = "medium"
	default:
		risk.RiskLevel = "low"
	}

	return risk
}

// isBoundToClusterAdmin returns true if any of the provided roles is the
// built-in cluster-admin ClusterRole.
func isBoundToClusterAdmin(roles []*graph.Node) bool {
	for _, r := range roles {
		if r.Metadata.IsClusterRole && r.Name == "cluster-admin" {
			return true
		}
	}
	return false
}

func generateRiskRecommendations(result *IdentityRiskResult) []string {
	var recs []string

	if result.Summary.WithClusterAdmin > 0 {
		recs = append(recs, "Review and restrict service accounts bound to cluster-admin role")
	}
	if result.Summary.WithSecretsAccess > 3 {
		recs = append(recs, "Reduce the number of identities with cluster-wide secrets access")
	}
	if result.Summary.OverprivilegedCount > 0 {
		recs = append(recs, "Apply least-privilege principles to over-privileged service accounts")
	}
	if result.Summary.WithCloudAccess > 0 {
		recs = append(recs, "Audit cloud IAM roles assumed by Kubernetes identities")
	}

	return recs
}
