package remediation

import (
	"github.com/nelssec/identity-chain/pkg/analysis"
)

func GenerateAllRemediations(
	rbacFindings []analysis.RBACFinding,
	podSecFindings []analysis.PodSecurityFinding,
	netPolFindings []analysis.NetworkPolicyFinding,
) *RemediationResult {
	result := &RemediationResult{
		TotalFindings: len(rbacFindings) + len(podSecFindings) + len(netPolFindings),
	}

	rbacRemediations := GenerateRBACRemediations(rbacFindings)
	podSecRemediations := GeneratePodSecurityRemediations(podSecFindings)
	netPolRemediations := GenerateNetworkPolicyRemediations(netPolFindings)

	result.Remediations = append(result.Remediations, rbacRemediations...)
	result.Remediations = append(result.Remediations, podSecRemediations...)
	result.Remediations = append(result.Remediations, netPolRemediations...)

	result.RemediableCount = len(result.Remediations)
	result.NonRemediable = result.TotalFindings - result.RemediableCount

	result.GenerateCombinedManifests()

	return result
}

func FilterBySeverity(result *RemediationResult, minSeverity string) *RemediationResult {
	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	minLevel := severityOrder[minSeverity]
	if minLevel == 0 && minSeverity != "info" {
		minLevel = 2
	}

	filtered := &RemediationResult{
		TotalFindings: result.TotalFindings,
	}

	for _, r := range result.Remediations {
		if severityOrder[r.Severity] >= minLevel {
			filtered.Remediations = append(filtered.Remediations, r)
		}
	}

	filtered.RemediableCount = len(filtered.Remediations)
	filtered.NonRemediable = result.NonRemediable
	filtered.GenerateCombinedManifests()

	return filtered
}

func FilterByType(result *RemediationResult, remType RemediationType) *RemediationResult {
	filtered := &RemediationResult{
		TotalFindings: result.TotalFindings,
	}

	for _, r := range result.Remediations {
		if r.Type == remType {
			filtered.Remediations = append(filtered.Remediations, r)
		}
	}

	filtered.RemediableCount = len(filtered.Remediations)
	filtered.NonRemediable = result.TotalFindings - filtered.RemediableCount
	filtered.GenerateCombinedManifests()

	return filtered
}

func FilterByNamespace(result *RemediationResult, namespace string) *RemediationResult {
	if namespace == "" {
		return result
	}

	filtered := &RemediationResult{
		TotalFindings: result.TotalFindings,
	}

	for _, r := range result.Remediations {
		if r.Resource.Namespace == namespace {
			filtered.Remediations = append(filtered.Remediations, r)
		}
	}

	filtered.RemediableCount = len(filtered.Remediations)
	filtered.NonRemediable = result.TotalFindings - filtered.RemediableCount
	filtered.GenerateCombinedManifests()

	return filtered
}
