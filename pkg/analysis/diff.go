package analysis

import "fmt"

// ---------------------------------------------------------------------------
// ScanFindings – a snapshot of all findings from one scan run
// ---------------------------------------------------------------------------

// ScanFindings aggregates findings from all analysis passes for snapshot/diff.
type ScanFindings struct {
	RBACFindings   []RBACFinding          `json:"rbac_findings"`
	PodSecFindings []PodSecurityFinding   `json:"pod_security_findings"`
	NetPolFindings []NetworkPolicyFinding `json:"network_policy_findings"`
	CloudFindings  []CloudIAMFinding      `json:"cloud_findings"`
}

// ---------------------------------------------------------------------------
// DiffResult – comparison between baseline and current findings
// ---------------------------------------------------------------------------

// DiffFinding is a finding entry in a diff result (simplified, cross-type).
type DiffFinding struct {
	CheckID   string `json:"check_id"`
	Title     string `json:"title"`
	Severity  string `json:"severity"`
	Namespace string `json:"namespace,omitempty"`
	Resource  string `json:"resource,omitempty"`
}

// DiffSummary holds high-level statistics for a diff.
type DiffSummary struct {
	Status        string `json:"status"`
	BaselineTotal int    `json:"baseline_total"`
	CurrentTotal  int    `json:"current_total"`
	NewCount      int    `json:"new_count"`
	ResolvedCount int    `json:"resolved_count"`
	UnchangedCount int   `json:"unchanged_count"`
}

// DiffResult is the output of ComputeDiff.
type DiffResult struct {
	Summary          DiffSummary   `json:"summary"`
	NewFindings      []DiffFinding `json:"new_findings"`
	ResolvedFindings []DiffFinding `json:"resolved_findings"`
	UnchangedCount   int           `json:"unchanged_count"`
}

// ComputeDiff compares two ScanFindings snapshots and returns what is new,
// what has been resolved, and what remains unchanged.
func ComputeDiff(baseline, current *ScanFindings) *DiffResult {
	result := &DiffResult{
		NewFindings:      []DiffFinding{},
		ResolvedFindings: []DiffFinding{},
	}

	baselineSet := fingerprintFindings(baseline)
	currentSet := fingerprintFindings(current)

	baselineTotal := len(baselineSet)
	currentTotal := len(currentSet)

	// New findings: in current but not baseline
	for fp, df := range currentSet {
		if _, exists := baselineSet[fp]; !exists {
			result.NewFindings = append(result.NewFindings, df)
		}
	}

	// Resolved: in baseline but not current
	for fp, df := range baselineSet {
		if _, exists := currentSet[fp]; !exists {
			result.ResolvedFindings = append(result.ResolvedFindings, df)
		}
	}

	result.UnchangedCount = baselineTotal - len(result.ResolvedFindings)
	if result.UnchangedCount < 0 {
		result.UnchangedCount = 0
	}

	result.Summary = DiffSummary{
		BaselineTotal:  baselineTotal,
		CurrentTotal:   currentTotal,
		NewCount:       len(result.NewFindings),
		ResolvedCount:  len(result.ResolvedFindings),
		UnchangedCount: result.UnchangedCount,
	}

	switch {
	case len(result.NewFindings) == 0 && len(result.ResolvedFindings) == 0:
		result.Summary.Status = "unchanged"
	case len(result.NewFindings) == 0:
		result.Summary.Status = "improved"
	case len(result.ResolvedFindings) == 0:
		result.Summary.Status = "degraded"
	case len(result.ResolvedFindings) > len(result.NewFindings):
		result.Summary.Status = "improved"
	default:
		result.Summary.Status = "degraded"
	}

	return result
}

// fingerprintFindings creates a deduplicated map of finding fingerprints to DiffFindings.
func fingerprintFindings(sf *ScanFindings) map[string]DiffFinding {
	m := make(map[string]DiffFinding)
	if sf == nil {
		return m
	}

	for _, f := range sf.RBACFindings {
		ns, res := "", ""
		if len(f.Affected) > 0 {
			ns = f.Affected[0].Namespace
			res = f.Affected[0].Name
		}
		fp := fmt.Sprintf("rbac:%s:%s:%s:%s", f.CheckID, f.Title, ns, res)
		m[fp] = DiffFinding{
			CheckID:   f.CheckID,
			Title:     f.Title,
			Severity:  string(f.Severity),
			Namespace: ns,
			Resource:  res,
		}
	}

	for _, f := range sf.PodSecFindings {
		ns, res := "", ""
		if len(f.Affected) > 0 {
			ns = f.Affected[0].Namespace
			res = f.Affected[0].Name
		}
		fp := fmt.Sprintf("podsec:%s:%s:%s:%s", f.CheckID, f.Title, ns, res)
		m[fp] = DiffFinding{
			CheckID:   f.CheckID,
			Title:     f.Title,
			Severity:  string(f.Severity),
			Namespace: ns,
			Resource:  res,
		}
	}

	for _, f := range sf.NetPolFindings {
		ns, res := "", ""
		if len(f.Affected) > 0 {
			ns = f.Affected[0].Namespace
			res = f.Affected[0].Name
		}
		fp := fmt.Sprintf("netpol:%s:%s:%s:%s", f.CheckID, f.Title, ns, res)
		m[fp] = DiffFinding{
			CheckID:   f.CheckID,
			Title:     f.Title,
			Severity:  string(f.Severity),
			Namespace: ns,
			Resource:  res,
		}
	}

	for _, f := range sf.CloudFindings {
		fp := fmt.Sprintf("cloud:%s:%s:%s", f.Title, f.Provider, f.RoleARN)
		m[fp] = DiffFinding{
			CheckID:   string(f.Category),
			Title:     f.Title,
			Severity:  string(f.Severity),
			Resource:  f.RoleARN,
		}
	}

	return m
}
