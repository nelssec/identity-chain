package analysis

import (
	"fmt"
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type ComplianceOptions struct {
	Namespace      string
	IncludeSystem  bool
	Frameworks     []ComplianceFramework
	IncludeCloud   bool
}

type ComplianceResult struct {
	Frameworks      []FrameworkCompliance   `json:"frameworks"`
	OverallScore    float64                 `json:"overall_score"`
	CriticalGaps    []ComplianceGap         `json:"critical_gaps"`
	ControlStatus   map[string]ControlResult `json:"control_status"`
	MappedFindings  []MappedFinding         `json:"mapped_findings"`
	Summary         ComplianceSummary       `json:"summary"`
	Recommendations []string                `json:"recommendations"`
}

type FrameworkCompliance struct {
	Framework         ComplianceFramework     `json:"framework"`
	Name              string                  `json:"name"`
	Version           string                  `json:"version"`
	TotalControls     int                     `json:"total_controls"`
	PassedControls    int                     `json:"passed_controls"`
	FailedControls    int                     `json:"failed_controls"`
	NotApplicable     int                     `json:"not_applicable"`
	CompliancePercent float64                 `json:"compliance_percent"`
	SectionResults    []SectionCompliance     `json:"section_results"`
	TopGaps           []ComplianceGap         `json:"top_gaps"`
}

type SectionCompliance struct {
	SectionID         string  `json:"section_id"`
	SectionTitle      string  `json:"section_title"`
	TotalControls     int     `json:"total_controls"`
	PassedControls    int     `json:"passed_controls"`
	FailedControls    int     `json:"failed_controls"`
	CompliancePercent float64 `json:"compliance_percent"`
}

type ComplianceGap struct {
	Framework    ComplianceFramework `json:"framework"`
	ControlID    string              `json:"control_id"`
	ControlTitle string              `json:"control_title"`
	Severity     graph.Severity      `json:"severity"`
	Finding      string              `json:"finding"`
	Remediation  string              `json:"remediation"`
	AffectedCount int                `json:"affected_count"`
}

type ControlResult struct {
	ControlID   string         `json:"control_id"`
	Status      string         `json:"status"`
	Findings    []string       `json:"findings"`
	Severity    graph.Severity `json:"severity"`
}

type MappedFinding struct {
	CheckID      string              `json:"check_id"`
	Title        string              `json:"title"`
	Severity     graph.Severity      `json:"severity"`
	CISControls  []string            `json:"cis_controls,omitempty"`
	NSACISARef   []string            `json:"nsa_cisa_ref,omitempty"`
	NISTControls []string            `json:"nist_controls,omitempty"`
	SOC2Controls []string            `json:"soc2_controls,omitempty"`
	PCIDSSReqs   []string            `json:"pci_dss_reqs,omitempty"`
}

type ComplianceSummary struct {
	TotalFrameworks    int                     `json:"total_frameworks"`
	AverageCompliance  float64                 `json:"average_compliance"`
	CriticalGapsCount  int                     `json:"critical_gaps_count"`
	HighGapsCount      int                     `json:"high_gaps_count"`
	TotalFindings      int                     `json:"total_findings"`
	ByFramework        map[string]float64      `json:"by_framework"`
}

func RunComplianceAnalysis(g *graph.Graph, opts ComplianceOptions) *ComplianceResult {
	result := &ComplianceResult{
		Frameworks:      []FrameworkCompliance{},
		ControlStatus:   make(map[string]ControlResult),
		MappedFindings:  []MappedFinding{},
		CriticalGaps:    []ComplianceGap{},
		Recommendations: []string{},
		Summary: ComplianceSummary{
			ByFramework: make(map[string]float64),
		},
	}

	if len(opts.Frameworks) == 0 {
		opts.Frameworks = GetAllFrameworks()
	}

	rbacResult := RunRBACAudit(g, RBACAuditOptions{
		Namespace:     opts.Namespace,
		IncludeSystem: opts.IncludeSystem,
	})

	podSecResult := RunPodSecurityAudit(g, PodSecurityOptions{
		Namespace:     opts.Namespace,
		IncludeSystem: opts.IncludeSystem,
	})

	platformResult := DetectPlatform(g)
	platformChecks := RunPlatformChecks(g, platformResult)

	exploitResult := AnalyzeExploitablePermissions(g, platformResult)

	allFindings := collectAllFindings(rbacResult, podSecResult, platformChecks, exploitResult)

	for _, finding := range allFindings {
		mapped := mapFindingToControls(finding)
		if mapped != nil {
			result.MappedFindings = append(result.MappedFindings, *mapped)
		}
	}

	for _, framework := range opts.Frameworks {
		fc := analyzeFrameworkCompliance(framework, result.MappedFindings, allFindings)
		result.Frameworks = append(result.Frameworks, fc)
		result.Summary.ByFramework[string(framework)] = fc.CompliancePercent

		for _, gap := range fc.TopGaps {
			if gap.Severity == graph.SeverityCritical {
				result.CriticalGaps = append(result.CriticalGaps, gap)
			}
		}
	}

	calculateComplianceSummary(result)
	generateComplianceRecommendations(result)

	return result
}

type genericFinding struct {
	CheckID     string
	Title       string
	Severity    graph.Severity
	Description string
	Remediation string
}

func collectAllFindings(rbac *RBACAuditResult, podSec *PodSecurityResult, platform *PlatformCheckResult, exploit *ExploitablePermResult) []genericFinding {
	var findings []genericFinding

	if rbac != nil {
		for _, f := range rbac.Findings {
			findings = append(findings, genericFinding{
				CheckID:     f.CheckID,
				Title:       f.Title,
				Severity:    f.Severity,
				Description: f.Description,
				Remediation: f.Remediation,
			})
		}
	}

	if podSec != nil {
		for _, f := range podSec.Findings {
			findings = append(findings, genericFinding{
				CheckID:     f.CheckID,
				Title:       f.Title,
				Severity:    f.Severity,
				Description: f.Description,
				Remediation: f.Remediation,
			})
		}
	}

	if platform != nil {
		for _, f := range platform.Findings {
			if !f.Passed {
				findings = append(findings, genericFinding{
					CheckID:     f.CheckID,
					Title:       f.Title,
					Severity:    f.Severity,
					Description: f.Description,
					Remediation: f.Remediation,
				})
			}
		}
	}

	if exploit != nil {
		for _, f := range exploit.Findings {
			findings = append(findings, genericFinding{
				CheckID:     f.ID,
				Title:       f.Title,
				Severity:    f.Severity,
				Description: f.Description,
				Remediation: f.Remediation,
			})
		}
	}

	return findings
}

func mapFindingToControls(finding genericFinding) *MappedFinding {
	checkID := finding.CheckID
	if strings.Contains(checkID, "-") {
		parts := strings.Split(checkID, "-")
		if len(parts) > 0 {
			checkID = parts[0]
		}
	}

	mapping := GetControlsForCheck(checkID)
	if mapping == nil {
		for prefix := range CheckControlMappings {
			if strings.HasPrefix(finding.CheckID, prefix) {
				mapping = GetControlsForCheck(prefix)
				break
			}
		}
	}

	if mapping == nil {
		return nil
	}

	return &MappedFinding{
		CheckID:      finding.CheckID,
		Title:        finding.Title,
		Severity:     finding.Severity,
		CISControls:  mapping.CISControls,
		NSACISARef:   mapping.NSACISARef,
		NISTControls: mapping.NISTControls,
		SOC2Controls: mapping.SOC2Controls,
		PCIDSSReqs:   mapping.PCIDSSReqs,
	}
}

func analyzeFrameworkCompliance(framework ComplianceFramework, mappedFindings []MappedFinding, allFindings []genericFinding) FrameworkCompliance {
	info := SupportedFrameworks[framework]

	fc := FrameworkCompliance{
		Framework:      framework,
		Name:           info.Name,
		Version:        info.Version,
		SectionResults: []SectionCompliance{},
		TopGaps:        []ComplianceGap{},
	}

	controlFindings := make(map[string][]MappedFinding)

	for _, mf := range mappedFindings {
		var controls []string
		switch framework {
		case FrameworkCIS:
			controls = mf.CISControls
		case FrameworkNSACISA:
			controls = mf.NSACISARef
		case FrameworkNIST:
			controls = mf.NISTControls
		case FrameworkSOC2:
			controls = mf.SOC2Controls
		case FrameworkPCIDSS:
			controls = mf.PCIDSSReqs
		}

		for _, ctrl := range controls {
			controlFindings[ctrl] = append(controlFindings[ctrl], mf)
		}
	}

	allControls := getFrameworkControls(framework)
	fc.TotalControls = len(allControls)

	for _, ctrl := range allControls {
		findings := controlFindings[ctrl]
		if len(findings) == 0 {
			fc.PassedControls++
		} else {
			fc.FailedControls++

			maxSeverity := graph.SeverityLow
			for _, f := range findings {
				if severityValue[f.Severity] > severityValue[maxSeverity] {
					maxSeverity = f.Severity
				}
			}

			fc.TopGaps = append(fc.TopGaps, ComplianceGap{
				Framework:     framework,
				ControlID:     ctrl,
				ControlTitle:  getControlTitle(framework, ctrl),
				Severity:      maxSeverity,
				Finding:       findings[0].Title,
				Remediation:   getRemediationForFindings(findings, allFindings),
				AffectedCount: len(findings),
			})
		}
	}

	if fc.TotalControls > 0 {
		fc.CompliancePercent = float64(fc.PassedControls) / float64(fc.TotalControls) * 100
	}

	sort.Slice(fc.TopGaps, func(i, j int) bool {
		return severityValue[fc.TopGaps[i].Severity] > severityValue[fc.TopGaps[j].Severity]
	})

	if len(fc.TopGaps) > 10 {
		fc.TopGaps = fc.TopGaps[:10]
	}

	for _, section := range info.Sections {
		sc := SectionCompliance{
			SectionID:    section.ID,
			SectionTitle: section.Title,
		}

		for _, ctrl := range allControls {
			if strings.HasPrefix(ctrl, section.ID) {
				sc.TotalControls++
				if len(controlFindings[ctrl]) == 0 {
					sc.PassedControls++
				} else {
					sc.FailedControls++
				}
			}
		}

		if sc.TotalControls > 0 {
			sc.CompliancePercent = float64(sc.PassedControls) / float64(sc.TotalControls) * 100
		}

		fc.SectionResults = append(fc.SectionResults, sc)
	}

	return fc
}

func getFrameworkControls(framework ComplianceFramework) []string {
	controlSet := make(map[string]bool)

	for _, mapping := range CheckControlMappings {
		var controls []string
		switch framework {
		case FrameworkCIS:
			controls = mapping.CISControls
		case FrameworkNSACISA:
			controls = mapping.NSACISARef
		case FrameworkNIST:
			controls = mapping.NISTControls
		case FrameworkSOC2:
			controls = mapping.SOC2Controls
		case FrameworkPCIDSS:
			controls = mapping.PCIDSSReqs
		}

		for _, ctrl := range controls {
			controlSet[ctrl] = true
		}
	}

	var controls []string
	for ctrl := range controlSet {
		controls = append(controls, ctrl)
	}
	sort.Strings(controls)

	return controls
}

func getControlTitle(framework ComplianceFramework, controlID string) string {
	switch framework {
	case FrameworkCIS:
		return getCISControlTitle(controlID)
	case FrameworkNSACISA:
		return getNSACISAControlTitle(controlID)
	case FrameworkNIST:
		return getNISTControlTitle(controlID)
	case FrameworkSOC2:
		return getSOC2ControlTitle(controlID)
	case FrameworkPCIDSS:
		return getPCIDSSControlTitle(controlID)
	}
	return controlID
}

func getCISControlTitle(id string) string {
	titles := map[string]string{
		"5.1.1": "Ensure cluster-admin role is only used where required",
		"5.1.2": "Minimize access to secrets",
		"5.1.3": "Minimize wildcard use in Roles and ClusterRoles",
		"5.1.4": "Minimize access to create pods",
		"5.1.5": "Ensure default service accounts are not actively used",
		"5.1.6": "Ensure Service Account Tokens are only mounted where necessary",
		"5.1.8": "Limit use of the Bind, Impersonate and Escalate permissions",
		"5.2.1": "Minimize the admission of privileged containers",
		"5.2.2": "Minimize the admission of containers wishing to share host process ID namespace",
		"5.2.3": "Minimize the admission of containers wishing to share host IPC namespace",
		"5.2.4": "Minimize the admission of containers wishing to share host network namespace",
		"5.2.5": "Minimize the admission of containers with allowPrivilegeEscalation",
		"5.2.6": "Minimize the admission of root containers",
		"5.2.7": "Minimize the admission of containers with NET_RAW capability",
		"5.2.8": "Minimize the admission of containers with added capabilities",
		"5.2.9": "Minimize the admission of containers with capabilities assigned",
		"5.2.10": "Minimize the admission of containers with seccomp profiles",
		"5.2.11": "Minimize the admission of Windows HostProcess containers",
		"5.3.1": "Ensure CNI supports Network Policies",
		"5.3.2": "Ensure default deny NetworkPolicy for all namespaces",
		"5.3.3": "Ensure NetworkPolicy is configured for all namespaces",
		"5.4.1": "Prefer using secrets as files over environment variables",
		"5.4.2": "Consider external secret storage",
		"5.4.3": "Minimize the use of secretKeyRef in environment variables",
	}
	if title, ok := titles[id]; ok {
		return title
	}
	return id
}

func getNSACISAControlTitle(id string) string {
	titles := map[string]string{
		"IAM-1":  "Use role-based access control",
		"IAM-2":  "Use strong authentication",
		"IAM-3":  "Limit privileges",
		"IAM-4":  "Minimize access to create pods",
		"IAM-5":  "Disable service account token automount",
		"IAM-6":  "Restrict escalate/bind/impersonate",
		"POD-1":  "Use non-root containers",
		"POD-2":  "Use read-only root filesystem",
		"POD-3":  "Minimize container capabilities",
		"POD-4":  "Disable host namespace sharing",
		"POD-5":  "Disable privilege escalation",
		"NET-1":  "Use network policies",
		"NET-2":  "Encrypt traffic",
		"NET-3":  "Segment networks",
		"SEC-1":  "Protect secrets",
		"SEC-2":  "Rotate credentials",
		"CLOUD-1": "Use workload identity",
		"CLOUD-2": "Minimize cloud permissions",
	}
	if title, ok := titles[id]; ok {
		return title
	}
	return id
}

func getNISTControlTitle(id string) string {
	titles := map[string]string{
		"AC-2":     "Account Management",
		"AC-2(1)":  "Account Management | Automated System Account Management",
		"AC-2(2)":  "Account Management | Automated Temporary and Emergency Account Management",
		"AC-2(3)":  "Account Management | Disable Accounts",
		"AC-2(4)":  "Account Management | Automated Audit Actions",
		"AC-2(7)":  "Account Management | Privileged User Accounts",
		"AC-2(12)": "Account Management | Account Monitoring for Atypical Usage",
		"AC-3":     "Access Enforcement",
		"AC-3(3)":  "Access Enforcement | Mandatory Access Control",
		"AC-3(4)":  "Access Enforcement | Discretionary Access Control",
		"AC-4":     "Information Flow Enforcement",
		"AC-6":     "Least Privilege",
		"AC-6(1)":  "Least Privilege | Authorize Access to Security Functions",
		"AC-6(2)":  "Least Privilege | Non-privileged Access for Nonsecurity Functions",
		"AC-6(5)":  "Least Privilege | Privileged Accounts",
		"AC-6(9)":  "Least Privilege | Log Use of Privileged Functions",
		"AC-6(10)": "Least Privilege | Prohibit Non-privileged Users from Executing Privileged Functions",
		"AC-17":    "Remote Access",
		"SC-4":     "Information in Shared System Resources",
		"SC-7":     "Boundary Protection",
		"SC-7(4)":  "Boundary Protection | External Telecommunications Services",
		"SC-7(5)":  "Boundary Protection | Deny by Default / Allow by Exception",
		"SC-28":    "Protection of Information at Rest",
		"SC-28(1)": "Protection of Information at Rest | Cryptographic Protection",
		"CM-7":     "Least Functionality",
		"CM-7(1)":  "Least Functionality | Periodic Review",
		"IA-5":     "Authenticator Management",
	}
	if title, ok := titles[id]; ok {
		return title
	}
	return id
}

func getSOC2ControlTitle(id string) string {
	titles := map[string]string{
		"CC6.1": "Logical Access Security Software, Infrastructure, and Architectures",
		"CC6.2": "Prior to Issuing System Credentials",
		"CC6.3": "Logical Access Security Registration and Authorization",
		"CC6.6": "Logical Access Security Measures Against Threats",
		"CC6.7": "Logical Access Security Transmission Protection",
	}
	if title, ok := titles[id]; ok {
		return title
	}
	return id
}

func getPCIDSSControlTitle(id string) string {
	titles := map[string]string{
		"1.1":   "Network Security Standards",
		"1.2":   "Network Security Controls Configuration",
		"1.2.1": "Inbound and Outbound Traffic Restrictions",
		"1.3":   "Network Access Controls",
		"1.3.1": "Inbound Traffic Restriction",
		"2.2":   "System Components Configured Securely",
		"2.2.1": "Vendor Defaults Changed",
		"2.2.2": "Primary Functions Separated",
		"2.2.3": "Security Parameters Configured",
		"2.2.4": "Unnecessary Functionality Removed",
		"2.3":   "Wireless Environments Secured",
		"3.4":   "PAN Rendered Unreadable",
		"3.5":   "Keys Used to Protect Stored Data",
		"6.2":   "Secure Development",
		"7.1":   "Access Control Systems",
		"7.1.1": "Access Control Policy",
		"7.1.2": "Privileged Access Restricted",
		"7.1.3": "Access Based on Job Classification",
		"7.1.4": "Approval for Access",
		"7.2":   "Access Control Systems Configured",
		"7.2.1": "Access Control System Coverage",
		"7.2.2": "Assignment of Privileges",
		"8.2":   "User Authentication",
	}
	if title, ok := titles[id]; ok {
		return title
	}
	return id
}

func getRemediationForFindings(mappedFindings []MappedFinding, allFindings []genericFinding) string {
	if len(mappedFindings) == 0 {
		return "Review and remediate the related security findings"
	}

	for _, af := range allFindings {
		if af.CheckID == mappedFindings[0].CheckID && af.Remediation != "" {
			return af.Remediation
		}
	}

	return "Address the security findings related to this control"
}

func calculateComplianceSummary(result *ComplianceResult) {
	result.Summary.TotalFrameworks = len(result.Frameworks)
	result.Summary.TotalFindings = len(result.MappedFindings)

	var totalCompliance float64
	for _, fc := range result.Frameworks {
		totalCompliance += fc.CompliancePercent
	}

	if result.Summary.TotalFrameworks > 0 {
		result.Summary.AverageCompliance = totalCompliance / float64(result.Summary.TotalFrameworks)
	}

	for _, gap := range result.CriticalGaps {
		if gap.Severity == graph.SeverityCritical {
			result.Summary.CriticalGapsCount++
		} else if gap.Severity == graph.SeverityHigh {
			result.Summary.HighGapsCount++
		}
	}

	for _, fc := range result.Frameworks {
		for _, gap := range fc.TopGaps {
			if gap.Severity == graph.SeverityCritical {
				result.Summary.CriticalGapsCount++
			} else if gap.Severity == graph.SeverityHigh {
				result.Summary.HighGapsCount++
			}
		}
	}

	result.OverallScore = result.Summary.AverageCompliance
}

func generateComplianceRecommendations(result *ComplianceResult) {
	if result.Summary.CriticalGapsCount > 0 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Address %d critical compliance gaps immediately", result.Summary.CriticalGapsCount))
	}

	lowestCompliance := ""
	lowestScore := 100.0
	for fw, score := range result.Summary.ByFramework {
		if score < lowestScore {
			lowestScore = score
			lowestCompliance = fw
		}
	}

	if lowestCompliance != "" && lowestScore < 80 {
		result.Recommendations = append(result.Recommendations,
			fmt.Sprintf("Focus on improving %s compliance (currently %.1f%%)", lowestCompliance, lowestScore))
	}

	for _, fc := range result.Frameworks {
		if fc.CompliancePercent < 70 {
			result.Recommendations = append(result.Recommendations,
				fmt.Sprintf("%s compliance is below 70%% - review section-level failures", fc.Name))
		}
	}

	if result.Summary.TotalFindings > 20 {
		result.Recommendations = append(result.Recommendations,
			"High number of findings detected - consider systematic RBAC review")
	}
}
