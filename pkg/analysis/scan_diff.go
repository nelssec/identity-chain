package analysis

import (
	"fmt"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// ────────────────────────────────────────────────────────────────────────────
// ScanFindings is a normalised container for multi-domain scan results used
// by ComputeDiff to compare two snapshots.
// ────────────────────────────────────────────────────────────────────────────

// ScanFindings holds findings from multiple audit domains.
type ScanFindings struct {
	RBACFindings   []RBACFinding          `json:"rbac_findings,omitempty"`
	PodSecFindings []PodSecurityFinding   `json:"pod_sec_findings,omitempty"`
	NetPolFindings []NetworkPolicyFinding `json:"net_pol_findings,omitempty"`
	CloudFindings  []CloudIAMFinding      `json:"cloud_findings,omitempty"`
}

// DiffFinding is a generic finding that can be emitted from either dataset.
type DiffFinding struct {
	CheckID   string         `json:"check_id"`
	Title     string         `json:"title"`
	Severity  graph.Severity `json:"severity"`
	Namespace string         `json:"namespace,omitempty"`
	Resource  string         `json:"resource,omitempty"`
}

// DiffSummary holds aggregate statistics for the comparison.
type DiffSummary struct {
	Status        string `json:"status"`
	BaselineTotal int    `json:"baseline_total"`
	CurrentTotal  int    `json:"current_total"`
	NewCount      int    `json:"new_count"`
	ResolvedCount int    `json:"resolved_count"`
}

// DiffResult is the top-level return value of ComputeDiff.
type DiffResult struct {
	NewFindings      []DiffFinding `json:"new_findings"`
	ResolvedFindings []DiffFinding `json:"resolved_findings"`
	UnchangedCount   int           `json:"unchanged_count"`
	Summary          DiffSummary   `json:"summary"`
}

// ────────────────────────────────────────────────────────────────────────────
// ComputeDiff compares two ScanFindings snapshots and returns the delta.
// ────────────────────────────────────────────────────────────────────────────

func ComputeDiff(baseline, current *ScanFindings) *DiffResult {
	result := &DiffResult{
		NewFindings:      []DiffFinding{},
		ResolvedFindings: []DiffFinding{},
	}

	baselineMap := flattenFindings(baseline)
	currentMap := flattenFindings(current)

	// Findings that exist in current but not in baseline → new.
	for key, f := range currentMap {
		if _, exists := baselineMap[key]; !exists {
			result.NewFindings = append(result.NewFindings, f)
		} else {
			result.UnchangedCount++
		}
	}

	// Findings that exist in baseline but not in current → resolved.
	for key, f := range baselineMap {
		if _, exists := currentMap[key]; !exists {
			result.ResolvedFindings = append(result.ResolvedFindings, f)
		}
	}

	baselineTotal := len(baselineMap)
	currentTotal := len(currentMap)

	result.Summary = DiffSummary{
		BaselineTotal: baselineTotal,
		CurrentTotal:  currentTotal,
		NewCount:      len(result.NewFindings),
		ResolvedCount: len(result.ResolvedFindings),
	}

	if len(result.NewFindings) > 0 {
		result.Summary.Status = "DEGRADED"
	} else if len(result.ResolvedFindings) > 0 {
		result.Summary.Status = "IMPROVED"
	} else {
		result.Summary.Status = "UNCHANGED"
	}

	return result
}

// flattenFindings converts a ScanFindings snapshot into a keyed map of
// DiffFindings for easy set-difference computation.
func flattenFindings(sf *ScanFindings) map[string]DiffFinding {
	out := make(map[string]DiffFinding)

	if sf == nil {
		return out
	}

	for _, f := range sf.RBACFindings {
		key := fmt.Sprintf("rbac:%s:%s", f.CheckID, affectedKey(f.Affected))
		out[key] = DiffFinding{
			CheckID:  f.CheckID,
			Title:    f.Title,
			Severity: f.Severity,
		}
	}

	for _, f := range sf.PodSecFindings {
		ns, name := "", ""
		if len(f.Affected) > 0 {
			ns = f.Affected[0].Namespace
			name = f.Affected[0].Name
		}
		key := fmt.Sprintf("podsec:%s:%s/%s", f.CheckID, ns, name)
		out[key] = DiffFinding{
			CheckID:   f.CheckID,
			Title:     f.Title,
			Severity:  f.Severity,
			Namespace: ns,
			Resource:  name,
		}
	}

	for _, f := range sf.NetPolFindings {
		ns, name := "", ""
		if len(f.Affected) > 0 {
			ns = f.Affected[0].Namespace
			name = f.Affected[0].Name
		}
		key := fmt.Sprintf("netpol:%s:%s/%s", f.CheckID, ns, name)
		out[key] = DiffFinding{
			CheckID:   f.CheckID,
			Title:     f.Title,
			Severity:  f.Severity,
			Namespace: ns,
			Resource:  name,
		}
	}

	for _, f := range sf.CloudFindings {
		key := fmt.Sprintf("cloud:%s:%s", f.RoleARN, f.Title)
		out[key] = DiffFinding{
			CheckID:  f.Title,
			Title:    f.Title,
			Severity: f.Severity,
		}
	}

	return out
}

func affectedKey(affected []AffectedResource) string {
	if len(affected) == 0 {
		return ""
	}
	return fmt.Sprintf("%s/%s/%s", affected[0].Kind, affected[0].Namespace, affected[0].Name)
}
