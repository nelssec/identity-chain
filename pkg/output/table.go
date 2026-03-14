package output

import (
	"fmt"
	"io"
	"os"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/briandowns/spinner"
	"github.com/fatih/color"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

// TableWriter writes analysis results as formatted ASCII tables with optional color.
type TableWriter struct {
	w       io.Writer
	verbose bool
	noColor bool
}

// TableOptions configures table output behavior.
type TableOptions struct {
	Verbose bool
	NoColor bool
}

// NewTableWriter creates a TableWriter with default options.
func NewTableWriter(w io.Writer) *TableWriter {
	return NewTableWriterWithOptions(w, TableOptions{})
}

// NewTableWriterWithOptions creates a TableWriter with the given options.
func NewTableWriterWithOptions(w io.Writer, opts TableOptions) *TableWriter {
	nc := opts.NoColor
	if !nc {
		// Respect NO_COLOR env var (https://no-color.org)
		if _, ok := os.LookupEnv("NO_COLOR"); ok {
			nc = true
		}
	}
	if nc {
		color.NoColor = true
	}
	return &TableWriter{w: w, verbose: opts.Verbose, noColor: nc}
}

// color helpers using fatih/color
var (
	criticalColor = color.New(color.FgRed, color.Bold)
	highColor     = color.New(color.FgRed)
	mediumColor   = color.New(color.FgYellow)
	lowColor      = color.New(color.FgCyan)
	infoColor     = color.New(color.FgWhite)
	headerColor   = color.New(color.Bold)
)

func severityColor(s graph.Severity) string {
	switch s {
	case graph.SeverityCritical:
		return criticalColor.Sprint(string(s))
	case graph.SeverityHigh:
		return highColor.Sprint(string(s))
	case graph.SeverityMedium:
		return mediumColor.Sprint(string(s))
	case graph.SeverityLow:
		return lowColor.Sprint(string(s))
	default:
		return infoColor.Sprint(string(s))
	}
}

func severityColorStr(s string) string {
	switch strings.ToLower(s) {
	case "critical":
		return criticalColor.Sprint(s)
	case "high":
		return highColor.Sprint(s)
	case "medium":
		return mediumColor.Sprint(s)
	case "low":
		return lowColor.Sprint(s)
	default:
		return infoColor.Sprint(s)
	}
}

// Spinner creates and starts a progress spinner on stderr. Returns a stop function.
func Spinner(msg string) func() {
	// Only show spinner if stderr is a terminal
	if !isTerminal(os.Stderr) {
		return func() {}
	}
	s := spinner.New(spinner.CharSets[14], 100*time.Millisecond, spinner.WithWriter(os.Stderr))
	s.Suffix = " " + msg
	s.Start()
	var once sync.Once
	return func() {
		once.Do(func() { s.Stop() })
	}
}

// isTerminal checks if a file is a terminal (best-effort).
func isTerminal(f *os.File) bool {
	stat, err := f.Stat()
	if err != nil {
		return false
	}
	return (stat.Mode() & os.ModeCharDevice) != 0
}

func (t *TableWriter) WriteBlastResult(result *analysis.BlastResult) error {
	if result == nil {
		fmt.Fprintln(t.w, "No results found")
		return nil
	}

	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Blast Radius Analysis ==="))

	if result.SourceWorkload != nil {
		fmt.Fprintf(t.w, "Workload:        %s/%s (%s)\n",
			result.SourceWorkload.Namespace,
			result.SourceWorkload.Name,
			result.SourceWorkload.Metadata.WorkloadKind)
	}

	if result.ServiceAccount != nil {
		fmt.Fprintf(t.w, "ServiceAccount:  %s/%s\n",
			result.ServiceAccount.Namespace,
			result.ServiceAccount.Name)

		if result.ServiceAccount.HasCloudIdentity() {
			if result.ServiceAccount.Metadata.CloudRoleARN != "" {
				fmt.Fprintf(t.w, "AWS Role:        %s\n", result.ServiceAccount.Metadata.CloudRoleARN)
			}
			if result.ServiceAccount.Metadata.GCPServiceAccount != "" {
				fmt.Fprintf(t.w, "GCP SA:          %s\n", result.ServiceAccount.Metadata.GCPServiceAccount)
			}
			if result.ServiceAccount.Metadata.AzureManagedID != "" {
				fmt.Fprintf(t.w, "Azure MI:        %s\n", result.ServiceAccount.Metadata.AzureManagedID)
			}
		}
	}

	fmt.Fprintf(t.w, "Max Severity:    %s\n", severityColor(result.MaxSeverity))
	fmt.Fprintf(t.w, "K8s Permissions: %d\n", result.TotalK8sPerms)
	fmt.Fprintf(t.w, "Cloud Roles:     %d\n", result.TotalCloudPerms)

	if len(result.K8sResources) > 0 {
		fmt.Fprintf(t.w, "\n--- Kubernetes Resource Access ---\n\n")
		fmt.Fprintf(t.w, "%-30s %-30s %-20s %-10s\n", "RESOURCE", "VERBS", "VIA ROLE", "SEVERITY")
		fmt.Fprintf(t.w, "%-30s %-30s %-20s %-10s\n", "--------", "-----", "--------", "--------")

		for _, access := range result.K8sResources {
			resourceName := access.Resource.Name
			if access.Resource.Namespace != "" {
				resourceName = access.Resource.Namespace + "/" + resourceName
			}
			if len(resourceName) > 28 {
				resourceName = resourceName[:28] + ".."
			}
			verbs := strings.Join(access.Verbs, ", ")
			if len(verbs) > 28 {
				verbs = verbs[:28] + ".."
			}
			fmt.Fprintf(t.w, "%-30s %-30s %-20s %s\n",
				resourceName,
				verbs,
				access.ViaRole,
				severityColor(access.Severity))
		}
	}

	if len(result.CloudRoles) > 0 {
		fmt.Fprintf(t.w, "\n--- Cloud Role Access ---\n\n")
		fmt.Fprintf(t.w, "%-10s %-60s %-10s\n", "PROVIDER", "ROLE ARN", "SEVERITY")
		fmt.Fprintf(t.w, "%-10s %-60s %-10s\n", "--------", "--------", "--------")

		for _, access := range result.CloudRoles {
			roleARN := access.RoleARN
			if len(roleARN) > 58 {
				roleARN = roleARN[:58] + ".."
			}
			fmt.Fprintf(t.w, "%-10s %-60s %s\n",
				access.Provider,
				roleARN,
				severityColor(access.Severity))
		}
	}

	fmt.Fprintln(t.w)
	return nil
}

func (t *TableWriter) WriteBlastResults(results []*analysis.BlastResult) error {
	if len(results) == 0 {
		fmt.Fprintln(t.w, "No workloads found")
		return nil
	}

	// Count severities and top namespaces
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	nsCounts := map[string]int{}

	for _, r := range results {
		switch r.MaxSeverity {
		case graph.SeverityCritical:
			criticalCount++
		case graph.SeverityHigh:
			highCount++
		case graph.SeverityMedium:
			mediumCount++
		case graph.SeverityLow:
			lowCount++
		}
		if r.SourceWorkload != nil {
			nsCounts[r.SourceWorkload.Namespace]++
		}
	}

	// Summary header
	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Workload Blast Radius Summary ==="))
	fmt.Fprintf(t.w, "Total Findings: %d | %s: %d | %s: %d | %s: %d | %s: %d\n",
		len(results),
		criticalColor.Sprint("CRITICAL"), criticalCount,
		highColor.Sprint("HIGH"), highCount,
		mediumColor.Sprint("MEDIUM"), mediumCount,
		lowColor.Sprint("LOW"), lowCount)

	// Top 3 affected namespaces
	type nsCount struct {
		ns    string
		count int
	}
	nsList := make([]nsCount, 0, len(nsCounts))
	for ns, c := range nsCounts {
		nsList = append(nsList, nsCount{ns, c})
	}
	sort.Slice(nsList, func(i, j int) bool { return nsList[i].count > nsList[j].count })
	if len(nsList) > 0 {
		top := 3
		if len(nsList) < top {
			top = len(nsList)
		}
		parts := make([]string, top)
		for i := 0; i < top; i++ {
			parts[i] = fmt.Sprintf("%s (%d)", nsList[i].ns, nsList[i].count)
		}
		fmt.Fprintf(t.w, "Top Namespaces: %s\n", strings.Join(parts, ", "))
	}

	fmt.Fprintln(t.w)

	fmt.Fprintf(t.w, "%-25s %-15s %-20s %-12s %-12s %-10s\n",
		"WORKLOAD", "NAMESPACE", "SERVICE ACCOUNT", "K8S PERMS", "CLOUD ROLES", "SEVERITY")
	fmt.Fprintf(t.w, "%-25s %-15s %-20s %-12s %-12s %-10s\n",
		"--------", "---------", "---------------", "---------", "-----------", "--------")

	for _, result := range results {
		workloadName := ""
		namespace := ""
		saName := ""

		if result.SourceWorkload != nil {
			workloadName = result.SourceWorkload.Name
			if len(workloadName) > 23 {
				workloadName = workloadName[:23] + ".."
			}
			namespace = result.SourceWorkload.Namespace
			if len(namespace) > 13 {
				namespace = namespace[:13] + ".."
			}
		}
		if result.ServiceAccount != nil {
			saName = result.ServiceAccount.Name
			if len(saName) > 18 {
				saName = saName[:18] + ".."
			}
		}

		fmt.Fprintf(t.w, "%-25s %-15s %-20s %-12d %-12d %s\n",
			workloadName,
			namespace,
			saName,
			result.TotalK8sPerms,
			result.TotalCloudPerms,
			severityColor(result.MaxSeverity))
	}

	fmt.Fprintf(t.w, "\nTotal: %d workloads | Critical: %d | High: %d\n\n", len(results), criticalCount, highCount)

	return nil
}

func (t *TableWriter) WriteGraph(g *graph.Graph) error {
	stats := g.Stats()
	return t.WriteStats(stats)
}

func (t *TableWriter) WriteStats(stats graph.GraphStats) error {
	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Graph Statistics ==="))
	fmt.Fprintf(t.w, "Total Nodes: %d\n", stats.TotalNodes)
	fmt.Fprintf(t.w, "Total Edges: %d\n\n", stats.TotalEdges)

	fmt.Fprintln(t.w, "Node Counts:")
	for nodeType, count := range stats.NodeCounts {
		fmt.Fprintf(t.w, "  %-20s %d\n", nodeType, count)
	}

	fmt.Fprintln(t.w, "\nEdge Counts:")
	for edgeType, count := range stats.EdgeCounts {
		fmt.Fprintf(t.w, "  %-20s %d\n", edgeType, count)
	}

	fmt.Fprintln(t.w)
	return nil
}

func (t *TableWriter) WritePrivescResults(results []*analysis.PrivescResult) error {
	if len(results) == 0 {
		fmt.Fprintln(t.w, "No privilege escalation paths found.")
		return nil
	}

	summary := analysis.SummarizePrivescResults(results)
	fmt.Fprintf(t.w, "%s\n\n", headerColor.Sprint("=== Privilege Escalation Analysis ==="))
	fmt.Fprintf(t.w, "Workloads with privesc paths: %d\n", summary.WorkloadsWithPrivesc)
	fmt.Fprintf(t.w, "Critical paths: %s\n", criticalColor.Sprintf("%d", summary.CriticalPaths))
	fmt.Fprintf(t.w, "High severity paths: %s\n", highColor.Sprintf("%d", summary.HighPaths))

	if len(summary.TopVectors) > 0 {
		fmt.Fprintf(t.w, "\nTop Attack Vectors:\n")
		for i, v := range summary.TopVectors {
			if i >= 5 {
				break
			}
			fmt.Fprintf(t.w, "  %-30s %d occurrences\n", v.Vector.String(), v.Count)
		}
	}

	if !t.verbose {
		// Compact mode: one-liner per finding
		fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings (use -v for details) ==="))
		for _, r := range results {
			if r.SourceNode != nil {
				vectorCount := len(r.DirectVectors) + len(r.Paths)
				fmt.Fprintf(t.w, "  [%s] %s/%s — %d vectors\n",
					severityColor(r.MaxSeverity),
					r.SourceNode.Namespace, r.SourceNode.Name,
					vectorCount)
			}
		}
		fmt.Fprintln(t.w)
		return nil
	}

	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Detailed Findings ==="))
	for _, r := range results {
		if r.SourceNode != nil {
			fmt.Fprintf(t.w, "--------------------------------------------------------------\n")
			fmt.Fprintf(t.w, "[%s] %s/%s\n", severityColor(r.MaxSeverity), r.SourceNode.Namespace, r.SourceNode.Name)
		}

		for _, v := range r.DirectVectors {
			fmt.Fprintf(t.w, "   VECTOR: %s\n", v.Vector.String())
			fmt.Fprintf(t.w, "     %s\n", v.Description)
			fmt.Fprintf(t.w, "     Via: %s | Verbs: %v\n", v.Role.Name, v.Verbs)
		}

		for _, p := range r.Paths {
			fmt.Fprintf(t.w, "   PATH: %s (%s)\n", p.FinalPrivilege, severityColorStr(string(p.Severity)))
			for _, step := range p.Steps {
				fmt.Fprintf(t.w, "      Step %d: %s\n", step.StepNumber, step.Description)
			}
			if len(p.Mitigations) > 0 {
				fmt.Fprintf(t.w, "     Mitigation: %s\n", p.Mitigations[0])
			}
		}
		fmt.Fprintln(t.w)
	}

	return nil
}

func (t *TableWriter) WriteWhoCanResult(result *analysis.WhoCanResult) error {
	if result.TotalCount == 0 {
		fmt.Fprintf(t.w, "No subjects can %s %s", result.Verb, result.Resource)
		if result.Namespace != "" {
			fmt.Fprintf(t.w, " in namespace %s", result.Namespace)
		}
		fmt.Fprintln(t.w)
		return nil
	}

	fmt.Fprintf(t.w, "%s %s %s", headerColor.Sprint("=== Who Can"), result.Verb, result.Resource)
	if result.Namespace != "" {
		fmt.Fprintf(t.w, " (namespace: %s)", result.Namespace)
	}
	fmt.Fprintf(t.w, " ===\n\n")

	fmt.Fprintf(t.w, "Found %d subjects:\n\n", result.TotalCount)

	fmt.Fprintf(t.w, "%-50s %-20s %-15s %s\n", "SUBJECT", "VIA ROLE", "SEVERITY", "WORKLOADS")
	fmt.Fprintf(t.w, "%s\n", strings.Repeat("-", 100))

	for _, s := range result.Subjects {
		subject := s.Namespace + "/" + s.Name
		workloadCount := len(s.Workloads)
		workloadInfo := fmt.Sprintf("%d workloads", workloadCount)
		if workloadCount == 0 {
			workloadInfo = "(unused)"
		}

		roleType := ""
		if s.IsClusterRole {
			roleType = " (cluster)"
		}

		fmt.Fprintf(t.w, "%-50s %-20s %-15s %s\n",
			truncateString(subject, 50),
			truncateString(s.ViaRole+roleType, 20),
			severityColorStr(string(s.Severity)),
			workloadInfo)
	}

	return nil
}

func (t *TableWriter) WriteWhatCanResult(result *analysis.ReverseRBACResult) error {
	if len(result.Permissions) == 0 {
		fmt.Fprintf(t.w, "ServiceAccount %s/%s has no RBAC permissions.\n", result.Namespace, result.Subject)
		return nil
	}

	fmt.Fprintf(t.w, "%s %s/%s ===\n\n", headerColor.Sprint("=== Permissions for"), result.Namespace, result.Subject)
	fmt.Fprintf(t.w, "Max Severity: %s\n", severityColorStr(string(result.MaxSeverity)))
	fmt.Fprintf(t.w, "Total Verbs: %d\n", result.TotalVerbs)
	fmt.Fprintf(t.w, "Roles: %d\n\n", len(result.Roles))

	fmt.Fprintf(t.w, "%-30s %-40s %-15s %s\n", "RESOURCE", "VERBS", "SEVERITY", "VIA ROLE")
	fmt.Fprintf(t.w, "%s\n", strings.Repeat("-", 100))

	for _, p := range result.Permissions {
		verbs := strings.Join(p.Verbs, ", ")
		roleType := ""
		if p.IsClusterRole {
			roleType = " (cluster)"
		}
		fmt.Fprintf(t.w, "%-30s %-40s %-15s %s\n",
			truncateString(p.Resource, 30),
			truncateString(verbs, 40),
			severityColorStr(string(p.Severity)),
			p.ViaRole+roleType)
	}

	return nil
}

func (t *TableWriter) WriteRBACAuditResult(result *analysis.RBACAuditResult) error {
	fmt.Fprintf(t.w, "%s\n\n", headerColor.Sprint("=== RBAC Security Audit ==="))
	fmt.Fprintf(t.w, "Checks Run: %d\n", len(result.ChecksRun))
	fmt.Fprintf(t.w, "Total Findings: %d\n\n", result.TotalFindings)

	fmt.Fprintf(t.w, "Summary:\n")
	fmt.Fprintf(t.w, "  %s: %d\n", criticalColor.Sprint("Critical"), result.Summary.Critical)
	fmt.Fprintf(t.w, "  %s:     %d\n", highColor.Sprint("High"), result.Summary.High)
	fmt.Fprintf(t.w, "  %s:   %d\n", mediumColor.Sprint("Medium"), result.Summary.Medium)
	fmt.Fprintf(t.w, "  %s:      %d\n", lowColor.Sprint("Low"), result.Summary.Low)

	if result.TotalFindings == 0 {
		fmt.Fprintln(t.w, "\nNo security issues found.")
		return nil
	}

	if !t.verbose {
		fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings (use -v for details) ==="))
		for _, f := range result.Findings {
			fmt.Fprintf(t.w, "  [%s] %s — %s\n", severityColorStr(string(f.Severity)), f.CheckID, f.Title)
		}
		fmt.Fprintln(t.w)
		return nil
	}

	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings ==="))

	currentSeverity := ""
	for _, f := range result.Findings {
		if string(f.Severity) != currentSeverity {
			currentSeverity = string(f.Severity)
			fmt.Fprintf(t.w, "--- %s ---\n\n", severityColorStr(strings.ToUpper(currentSeverity)))
		}

		fmt.Fprintf(t.w, "[%s] %s\n", f.CheckID, f.Title)
		fmt.Fprintf(t.w, "   %s\n", f.Description)

		if len(f.Affected) > 0 {
			fmt.Fprintf(t.w, "   Affected (%d):\n", len(f.Affected))
			limit := 5
			if len(f.Affected) < limit {
				limit = len(f.Affected)
			}
			for i := 0; i < limit; i++ {
				a := f.Affected[i]
				fmt.Fprintf(t.w, "     - %s/%s: %s\n", a.Namespace, a.Name, a.Details)
			}
			if len(f.Affected) > 5 {
				fmt.Fprintf(t.w, "     ... and %d more\n", len(f.Affected)-5)
			}
		}

		if f.Remediation != "" {
			fmt.Fprintf(t.w, "   Remediation: %s\n", f.Remediation)
		}
		fmt.Fprintln(t.w)
	}

	return nil
}

func (t *TableWriter) WriteCloudAuditResult(result *analysis.CloudIAMAuditResult) error {
	fmt.Fprintf(t.w, "%s\n\n", headerColor.Sprint("=== Cloud IAM Security Audit ==="))
	fmt.Fprintf(t.w, "Roles Analyzed: %d\n", result.AnalyzedRoles)
	fmt.Fprintf(t.w, "Total Findings: %d\n\n", len(result.Findings))

	fmt.Fprintf(t.w, "Summary:\n")
	fmt.Fprintf(t.w, "  %s: %d\n", criticalColor.Sprint("Critical"), result.Summary.Critical)
	fmt.Fprintf(t.w, "  %s:     %d\n", highColor.Sprint("High"), result.Summary.High)
	fmt.Fprintf(t.w, "  %s:   %d\n", mediumColor.Sprint("Medium"), result.Summary.Medium)
	fmt.Fprintf(t.w, "  %s:      %d\n", lowColor.Sprint("Low"), result.Summary.Low)

	if len(result.Summary.ByProvider) > 0 {
		fmt.Fprintf(t.w, "\nBy Provider:\n")
		for provider, count := range result.Summary.ByProvider {
			fmt.Fprintf(t.w, "  %s: %d findings\n", provider, count)
		}
	}

	if len(result.Findings) == 0 {
		fmt.Fprintln(t.w, "\nNo cloud IAM security issues found.")
		return nil
	}

	if !t.verbose {
		fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings (use -v for details) ==="))
		for _, f := range result.Findings {
			fmt.Fprintf(t.w, "  [%s] %s — %s\n", severityColorStr(string(f.Severity)), f.Category, f.Title)
		}
		fmt.Fprintln(t.w)
		return nil
	}

	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings ==="))

	for _, f := range result.Findings {
		fmt.Fprintf(t.w, "[%s] %s\n", severityColorStr(string(f.Severity)), f.Title)
		fmt.Fprintf(t.w, "   Category: %s\n", f.Category)
		fmt.Fprintf(t.w, "   Role: %s\n", truncateString(f.RoleARN, 60))
		fmt.Fprintf(t.w, "   %s\n", f.Description)

		if f.Details != nil {
			for k, v := range f.Details {
				fmt.Fprintf(t.w, "   %s: %v\n", k, v)
			}
		}

		if f.Remediation != "" {
			fmt.Fprintf(t.w, "   Remediation: %s\n", f.Remediation)
		}
		fmt.Fprintln(t.w)
	}

	return nil
}

func truncateString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-2] + ".."
}

func (t *TableWriter) WritePodSecurityResult(result *analysis.PodSecurityResult) error {
	fmt.Fprintf(t.w, "%s\n\n", headerColor.Sprint("=== Pod Security Audit ==="))
	fmt.Fprintf(t.w, "Checks Run: %d\n", len(result.ChecksRun))
	fmt.Fprintf(t.w, "Total Findings: %d\n\n", result.TotalFindings)

	fmt.Fprintf(t.w, "Summary:\n")
	fmt.Fprintf(t.w, "  %s: %d\n", criticalColor.Sprint("Critical"), result.Summary.Critical)
	fmt.Fprintf(t.w, "  %s:     %d\n", highColor.Sprint("High"), result.Summary.High)
	fmt.Fprintf(t.w, "  %s:   %d\n", mediumColor.Sprint("Medium"), result.Summary.Medium)
	fmt.Fprintf(t.w, "  %s:      %d\n", lowColor.Sprint("Low"), result.Summary.Low)

	if len(result.Summary.ByCategory) > 0 {
		fmt.Fprintf(t.w, "\nBy Category:\n")
		for cat, count := range result.Summary.ByCategory {
			fmt.Fprintf(t.w, "  %s: %d findings\n", cat, count)
		}
	}

	if result.TotalFindings == 0 {
		fmt.Fprintln(t.w, "\nNo pod security issues found.")
		return nil
	}

	if !t.verbose {
		fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings (use -v for details) ==="))
		for _, f := range result.Findings {
			fmt.Fprintf(t.w, "  [%s] %s — %s\n", severityColorStr(string(f.Severity)), f.CheckID, f.Title)
		}
		fmt.Fprintln(t.w)
		return nil
	}

	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings ==="))

	currentSeverity := ""
	for _, f := range result.Findings {
		if string(f.Severity) != currentSeverity {
			currentSeverity = string(f.Severity)
			fmt.Fprintf(t.w, "--- %s ---\n\n", severityColorStr(strings.ToUpper(currentSeverity)))
		}

		fmt.Fprintf(t.w, "[%s] %s\n", f.CheckID, f.Title)
		fmt.Fprintf(t.w, "   %s\n", f.Description)

		if len(f.Affected) > 0 {
			fmt.Fprintf(t.w, "   Affected (%d):\n", len(f.Affected))
			limit := 5
			if len(f.Affected) < limit {
				limit = len(f.Affected)
			}
			for i := 0; i < limit; i++ {
				a := f.Affected[i]
				container := ""
				if a.Container != "" {
					container = "/" + a.Container
				}
				fmt.Fprintf(t.w, "     - %s %s/%s%s: %s\n", a.Kind, a.Namespace, a.Name, container, a.Details)
			}
			if len(f.Affected) > 5 {
				fmt.Fprintf(t.w, "     ... and %d more\n", len(f.Affected)-5)
			}
		}

		if f.Remediation != "" {
			fmt.Fprintf(t.w, "   Remediation: %s\n", f.Remediation)
		}
		fmt.Fprintln(t.w)
	}

	return nil
}

func (t *TableWriter) WriteNetworkPolicyResult(result *analysis.NetworkPolicyResult) error {
	fmt.Fprintf(t.w, "%s\n\n", headerColor.Sprint("=== Network Policy Audit ==="))
	fmt.Fprintf(t.w, "Checks Run: %d\n", len(result.ChecksRun))
	fmt.Fprintf(t.w, "Total Findings: %d\n", result.TotalFindings)
	fmt.Fprintf(t.w, "Network Policies: %d\n\n", result.Summary.TotalNetworkPolicies)

	fmt.Fprintf(t.w, "Summary:\n")
	fmt.Fprintf(t.w, "  %s: %d\n", criticalColor.Sprint("Critical"), result.Summary.Critical)
	fmt.Fprintf(t.w, "  %s:     %d\n", highColor.Sprint("High"), result.Summary.High)
	fmt.Fprintf(t.w, "  %s:   %d\n", mediumColor.Sprint("Medium"), result.Summary.Medium)
	fmt.Fprintf(t.w, "  %s:      %d\n", lowColor.Sprint("Low"), result.Summary.Low)
	fmt.Fprintf(t.w, "\n  Workloads without policy:     %d\n", result.Summary.WorkloadsWithoutPolicy)
	fmt.Fprintf(t.w, "  Externally exposed workloads: %d\n", result.Summary.WorkloadsExternallyExposed)

	if len(result.Summary.ByCategory) > 0 {
		fmt.Fprintf(t.w, "\nBy Category:\n")
		for cat, count := range result.Summary.ByCategory {
			fmt.Fprintf(t.w, "  %s: %d findings\n", cat, count)
		}
	}

	if result.TotalFindings == 0 {
		fmt.Fprintln(t.w, "\nNo network policy issues found.")
		return nil
	}

	if !t.verbose {
		fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings (use -v for details) ==="))
		for _, f := range result.Findings {
			fmt.Fprintf(t.w, "  [%s] %s — %s\n", severityColorStr(string(f.Severity)), f.CheckID, f.Title)
		}
		fmt.Fprintln(t.w)
		return nil
	}

	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Findings ==="))

	currentSeverity := ""
	for _, f := range result.Findings {
		if string(f.Severity) != currentSeverity {
			currentSeverity = string(f.Severity)
			fmt.Fprintf(t.w, "--- %s ---\n\n", severityColorStr(strings.ToUpper(currentSeverity)))
		}

		fmt.Fprintf(t.w, "[%s] %s\n", f.CheckID, f.Title)
		fmt.Fprintf(t.w, "   %s\n", f.Description)

		if len(f.Affected) > 0 {
			fmt.Fprintf(t.w, "   Affected (%d):\n", len(f.Affected))
			limit := 5
			if len(f.Affected) < limit {
				limit = len(f.Affected)
			}
			for i := 0; i < limit; i++ {
				a := f.Affected[i]
				services := ""
				if len(a.Services) > 0 {
					services = " via " + strings.Join(a.Services, ", ")
				}
				fmt.Fprintf(t.w, "     - %s %s/%s: %s%s\n", a.Kind, a.Namespace, a.Name, a.Details, services)
			}
			if len(f.Affected) > 5 {
				fmt.Fprintf(t.w, "     ... and %d more\n", len(f.Affected)-5)
			}
		}

		if f.Remediation != "" {
			fmt.Fprintf(t.w, "   Remediation: %s\n", f.Remediation)
		}
		fmt.Fprintln(t.w)
	}

	return nil
}

func (t *TableWriter) WriteAttackPathResults(results []*analysis.AttackPathResult) error {
	if len(results) == 0 {
		fmt.Fprintln(t.w, "No attack paths found.")
		return nil
	}

	summary := analysis.SummarizeAttackPaths(results)
	fmt.Fprintf(t.w, "%s\n\n", headerColor.Sprint("=== Attack Path Analysis ==="))
	fmt.Fprintf(t.w, "Workloads Analyzed: %d\n", summary.TotalWorkloads)
	fmt.Fprintf(t.w, "Workloads with Paths: %d\n", summary.WorkloadsWithPaths)
	fmt.Fprintf(t.w, "Total Attack Paths: %d\n\n", summary.TotalPaths)

	fmt.Fprintf(t.w, "Path Severity:\n")
	fmt.Fprintf(t.w, "  %s: %d\n", criticalColor.Sprint("Critical"), summary.CriticalPaths)
	fmt.Fprintf(t.w, "  %s:     %d\n", highColor.Sprint("High"), summary.HighPaths)
	fmt.Fprintf(t.w, "  Cloud:    %d\n", summary.CloudPaths)
	fmt.Fprintf(t.w, "  Cluster:  %d\n", summary.ClusterPaths)

	if len(summary.TopTechniques) > 0 {
		fmt.Fprintf(t.w, "\nTop Attack Techniques:\n")
		for _, tc := range summary.TopTechniques {
			fmt.Fprintf(t.w, "  %-30s %d\n", tc.Name, tc.Count)
		}
	}

	if len(summary.TopObjectives) > 0 {
		fmt.Fprintf(t.w, "\nTop Attack Objectives:\n")
		for _, obj := range summary.TopObjectives {
			fmt.Fprintf(t.w, "  %-40s %d\n", obj.Objective, obj.Count)
		}
	}

	if !t.verbose {
		fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Attack Paths (use -v for details) ==="))
		for _, r := range results {
			if len(r.Paths) == 0 {
				continue
			}
			workloadName := "unknown"
			namespace := "unknown"
			if r.SourceWorkload != nil {
				workloadName = r.SourceWorkload.Name
				namespace = r.SourceWorkload.Namespace
			}
			fmt.Fprintf(t.w, "  [%s] %s/%s — %d paths\n",
				severityColor(r.MaxSeverity), namespace, workloadName, r.TotalPaths)
		}
		fmt.Fprintln(t.w)
		return nil
	}

	fmt.Fprintf(t.w, "\n%s\n\n", headerColor.Sprint("=== Attack Paths by Workload ==="))

	for _, r := range results {
		if len(r.Paths) == 0 {
			continue
		}

		workloadName := "unknown"
		namespace := "unknown"
		if r.SourceWorkload != nil {
			workloadName = r.SourceWorkload.Name
			namespace = r.SourceWorkload.Namespace
		}

		fmt.Fprintf(t.w, "======================================================================\n")
		fmt.Fprintf(t.w, "Workload: %s/%s\n", namespace, workloadName)
		fmt.Fprintf(t.w, "Attack Paths: %d | Critical: %d | High: %d | Max Severity: %s\n",
			r.TotalPaths, r.CriticalPaths, r.HighPaths, severityColor(r.MaxSeverity))
		if r.CanReachCloud {
			fmt.Fprintf(t.w, "  Can reach CLOUD resources\n")
		}
		if r.CanReachCluster {
			fmt.Fprintf(t.w, "  Can reach CLUSTER-WIDE resources\n")
		}
		fmt.Fprintf(t.w, "======================================================================\n\n")

		for i, path := range r.Paths {
			fmt.Fprintf(t.w, "--- Path %d: %s ---\n", i+1, path.Name)
			fmt.Fprintf(t.w, "Objective: %s\n", path.Objective)
			fmt.Fprintf(t.w, "Severity: %s | Risk Score: %d\n", severityColor(path.MaxSeverity), path.RiskScore)

			if path.AffectsCloud {
				fmt.Fprintf(t.w, "  Affects cloud resources\n")
			}
			if path.AffectsCluster {
				fmt.Fprintf(t.w, "  Affects cluster-wide\n")
			}
			if path.CrossesNamespace {
				fmt.Fprintf(t.w, "  Crosses namespace boundaries\n")
			}

			fmt.Fprintf(t.w, "\nAttack Chain:\n")
			for _, step := range path.Steps {
				fmt.Fprintf(t.w, "  [%d] %s\n", step.StepNumber, step.Action)
				fmt.Fprintf(t.w, "      %s\n", step.Description)
				if step.MitreID != "" {
					fmt.Fprintf(t.w, "      MITRE ATT&CK: %s\n", step.MitreID)
				}
				if step.ViaRole != "" {
					fmt.Fprintf(t.w, "      Via: %s\n", step.ViaRole)
				}
				for _, detail := range step.Details {
					fmt.Fprintf(t.w, "      - %s\n", detail)
				}
			}

			if len(path.Mitigations) > 0 {
				fmt.Fprintf(t.w, "\nMitigations:\n")
				for _, m := range path.Mitigations {
					fmt.Fprintf(t.w, "  * %s\n", m)
				}
			}
			fmt.Fprintln(t.w)
		}
	}

	return nil
}
