package output

import (
	_ "embed"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

//go:embed assets/logo.png
var logoPNG []byte

// DashboardData contains all data for the unified dashboard
type DashboardData struct {
	BlastResults  []*analysis.BlastResult
	AttackPaths   []*analysis.AttackPathResult
	RBACAudit     *analysis.RBACAuditResult
	PodSecurity   *analysis.PodSecurityResult
	NetworkPolicy *analysis.NetworkPolicyResult
	CloudAudit    *analysis.CloudIAMAuditResult
	Permissions   *PermissionsData
	GraphStats    graph.GraphStats
	Graph         *graph.Graph // For D3 visualization
}

// PermissionsData holds results from WhoCan queries
type PermissionsData struct {
	SecretAccess    []*analysis.WhoCanResult // Who can get/list secrets
	PodExec         []*analysis.WhoCanResult // Who can exec into pods
	PodCreate       []*analysis.WhoCanResult // Who can create pods
	PodDelete       []*analysis.WhoCanResult // Who can delete pods
	ClusterAdmin    []*analysis.WhoCanResult // Who has cluster-admin like permissions
	RoleBindings    []*analysis.WhoCanResult // Who can create rolebindings
	Impersonate     []*analysis.WhoCanResult // Who can impersonate
	DangerousPerms  []DangerousPermission    // Summary of dangerous permissions
}

// DangerousPermission represents a subject with dangerous access
type DangerousPermission struct {
	Subject     string
	SubjectKind string
	Namespace   string
	Permission  string
	Severity    string
	Details     string
}

// Dashboard generates unified security dashboards
type Dashboard struct {
	w io.Writer
}

// NewDashboard creates a new dashboard generator
func NewDashboard(w io.Writer) *Dashboard {
	return &Dashboard{w: w}
}

// Generate creates the unified HTML dashboard
func (d *Dashboard) Generate(data DashboardData) error {
	// Build JSON data for each section
	dashData := d.buildDashboardData(data)

	jsonBytes, err := json.Marshal(dashData)
	if err != nil {
		return fmt.Errorf("failed to marshal dashboard data: %w", err)
	}

	// Encode logo as base64 for embedding in HTML
	logoBase64 := base64.StdEncoding.EncodeToString(logoPNG)

	html := fmt.Sprintf(dashboardHTMLTemplate,
		logoBase64,
		dashData.Summary.TotalWorkloads,
		dashData.Summary.CriticalFindings,
		dashData.Summary.HighFindings,
		dashData.Summary.AttackPaths,
		dashData.Summary.CloudRoles,
		dashData.Summary.PolicyViolations,
		string(jsonBytes))

	_, err = d.w.Write([]byte(html))
	return err
}

type dashboardJSON struct {
	Summary       summaryData        `json:"summary"`
	BlastRadius   blastRadiusData    `json:"blastRadius"`
	AttackPaths   attackPathsData    `json:"attackPaths"`
	Permissions   permissionsJSON    `json:"permissions"`
	RBACAudit     rbacAuditData      `json:"rbacAudit"`
	PodSecurity   podSecurityData    `json:"podSecurity"`
	NetworkPolicy networkPolicyData  `json:"networkPolicy"`
	CloudAudit    cloudAuditData     `json:"cloudAudit"`
	GraphData     graphVisualization `json:"graphData"`
}

type permissionsJSON struct {
	SecretAccess   []whoCanResultJSON    `json:"secretAccess"`
	PodExec        []whoCanResultJSON    `json:"podExec"`
	PodCreate      []whoCanResultJSON    `json:"podCreate"`
	PodDelete      []whoCanResultJSON    `json:"podDelete"`
	ClusterAdmin   []whoCanResultJSON    `json:"clusterAdmin"`
	RoleBindings   []whoCanResultJSON    `json:"roleBindings"`
	Impersonate    []whoCanResultJSON    `json:"impersonate"`
	DangerousPerms []dangerousPermJSON   `json:"dangerousPerms"`
	Summary        permissionsSummary    `json:"summary"`
}

type whoCanResultJSON struct {
	Verb       string           `json:"verb"`
	Resource   string           `json:"resource"`
	Namespace  string           `json:"namespace"`
	Subjects   []subjectJSON    `json:"subjects"`
	TotalCount int              `json:"totalCount"`
}

type subjectJSON struct {
	Kind      string `json:"kind"`
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	ViaRole   string `json:"viaRole"`
}

type dangerousPermJSON struct {
	Subject     string `json:"subject"`
	SubjectKind string `json:"subjectKind"`
	Namespace   string `json:"namespace"`
	Permission  string `json:"permission"`
	Severity    string `json:"severity"`
	Details     string `json:"details"`
}

type permissionsSummary struct {
	TotalDangerous   int `json:"totalDangerous"`
	CriticalCount    int `json:"criticalCount"`
	HighCount        int `json:"highCount"`
	SecretAccessors  int `json:"secretAccessors"`
	PodExecUsers     int `json:"podExecUsers"`
	ClusterAdmins    int `json:"clusterAdmins"`
}

type summaryData struct {
	TotalWorkloads     int            `json:"totalWorkloads"`
	CriticalFindings   int            `json:"criticalFindings"`
	HighFindings       int            `json:"highFindings"`
	MediumFindings     int            `json:"mediumFindings"`
	LowFindings        int            `json:"lowFindings"`
	AttackPaths        int            `json:"attackPaths"`
	CloudRoles         int            `json:"cloudRoles"`
	PolicyViolations   int            `json:"policyViolations"`
	ServiceAccounts    int            `json:"serviceAccounts"`
	Roles              int            `json:"roles"`
	NamespaceBreakdown map[string]int `json:"namespaceBreakdown"`
	SeverityBreakdown  map[string]int `json:"severityBreakdown"`
}

type blastRadiusData struct {
	Results []blastResultItem `json:"results"`
}

type blastResultItem struct {
	Workload       string               `json:"workload"`
	Namespace      string               `json:"namespace"`
	Kind           string               `json:"kind"`
	Severity       string               `json:"severity"`
	K8sPerms       int                  `json:"k8sPerms"`
	CloudRoles     int                  `json:"cloudRoles"`
	BlastRadius    []string             `json:"blastRadius"`
	ServiceAccount string               `json:"serviceAccount"`
	Identities     []identityItem       `json:"identities"`
	K8sResources   []k8sResourceItem    `json:"k8sResources"`
	CloudResources []cloudResourceItem  `json:"cloudResources"`
	RiskFactors    []string             `json:"riskFactors"`
}

type identityItem struct {
	Name           string `json:"name"`
	Namespace      string `json:"namespace"`
	Type           string `json:"type"`
	HasCloudAccess bool   `json:"hasCloudAccess"`
	CloudRoleARN   string `json:"cloudRoleArn"`
}

type k8sResourceItem struct {
	Resource  string   `json:"resource"`
	Namespace string   `json:"namespace"`
	Kind      string   `json:"kind"`
	Verbs     []string `json:"verbs"`
	ViaRole   string   `json:"viaRole"`
	Severity  string   `json:"severity"`
}

type cloudResourceItem struct {
	RoleARN    string   `json:"roleArn"`
	Provider   string   `json:"provider"`
	Services   []string `json:"services"`
	IsAdmin    bool     `json:"isAdmin"`
	PolicyARNs []string `json:"policyArns"`
}

type attackPathsData struct {
	Results []attackPathItem `json:"results"`
	Summary attackPathSummary `json:"summary"`
}

type attackPathItem struct {
	Workload       string          `json:"workload"`
	Namespace      string          `json:"namespace"`
	PathCount      int             `json:"pathCount"`
	Critical       int             `json:"critical"`
	High           int             `json:"high"`
	Objectives     []string        `json:"objectives"`
	AffectsCloud   bool            `json:"affectsCloud"`
	Paths          []attackPathDetail `json:"paths"`
}

type attackPathDetail struct {
	RiskScore    int              `json:"riskScore"`
	Severity     string           `json:"severity"`
	Objective    string           `json:"objective"`
	Steps        []attackStepItem `json:"steps"`
	Mitigations  []string         `json:"mitigations"`
	MitreTactics []string         `json:"mitreTactics"`
}

type attackStepItem struct {
	Order       int      `json:"order"`
	Action      string   `json:"action"`
	Target      string   `json:"target"`
	Technique   string   `json:"technique"`
	MitreID     string   `json:"mitreId"`
	Description string   `json:"description"`
}

type attackPathSummary struct {
	TotalPaths    int `json:"totalPaths"`
	CriticalPaths int `json:"criticalPaths"`
	HighPaths     int `json:"highPaths"`
	CloudPaths    int `json:"cloudPaths"`
}

type rbacAuditData struct {
	Findings []rbacFinding `json:"findings"`
	Summary  rbacSummary   `json:"summary"`
}

type rbacFinding struct {
	CheckID     string         `json:"checkId"`
	CheckName   string         `json:"checkName"`
	Severity    string         `json:"severity"`
	Subject     string         `json:"subject"`
	Namespace   string         `json:"namespace"`
	Description string         `json:"description"`
	Affected    []affectedItem `json:"affected"`
	Remediation string         `json:"remediation"`
}

type affectedItem struct {
	Name      string `json:"name"`
	Namespace string `json:"namespace"`
	Kind      string `json:"kind"`
	Details   string `json:"details"`
}

type rbacSummary struct {
	TotalFindings int `json:"totalFindings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
}

type podSecurityData struct {
	Findings []podSecFinding `json:"findings"`
	Summary  podSecSummary   `json:"summary"`
}

type podSecFinding struct {
	CheckID     string         `json:"checkId"`
	CheckName   string         `json:"checkName"`
	Severity    string         `json:"severity"`
	Workload    string         `json:"workload"`
	Namespace   string         `json:"namespace"`
	Container   string         `json:"container"`
	Details     string         `json:"details"`
	Affected    []affectedItem `json:"affected"`
	Remediation string         `json:"remediation"`
}

type podSecSummary struct {
	TotalFindings int `json:"totalFindings"`
	Critical      int `json:"critical"`
	High          int `json:"high"`
	Medium        int `json:"medium"`
	Low           int `json:"low"`
}

type networkPolicyData struct {
	Findings    []netPolFinding    `json:"findings"`
	Summary     netPolSummary      `json:"summary"`
	Suggestions []suggestedPolicy  `json:"suggestions"`
}

type suggestedPolicy struct {
	Workload     string   `json:"workload"`
	WorkloadKind string   `json:"workloadKind"`
	Namespace    string   `json:"namespace"`
	PolicyName   string   `json:"policyName"`
	YAML         string   `json:"yaml"`
	Description  string   `json:"description"`
	Services     []string `json:"services"`
}

type netPolFinding struct {
	CheckID   string         `json:"checkId"`
	CheckName string         `json:"checkName"`
	Severity  string         `json:"severity"`
	Workload  string         `json:"workload"`
	Namespace string         `json:"namespace"`
	Details   string         `json:"details"`
	Affected  []affectedItem `json:"affected"`
}

type netPolSummary struct {
	TotalFindings    int `json:"totalFindings"`
	WorkloadsNoPol   int `json:"workloadsNoPolicy"`
	ExternalExposed  int `json:"externalExposed"`
}

type cloudAuditData struct {
	Findings []cloudFinding `json:"findings"`
	Summary  cloudSummary   `json:"summary"`
}

type cloudFinding struct {
	Severity      string   `json:"severity"`
	RoleARN       string   `json:"roleArn"`
	Provider      string   `json:"provider"`
	Issue         string   `json:"issue"`
	Description   string   `json:"description"`
	ServiceAccounts []string `json:"serviceAccounts"`
	PolicyARNs    []string `json:"policyArns"`
}

type cloudSummary struct {
	TotalRoles          int            `json:"totalRoles"`
	AdminRoles          int            `json:"adminRoles"`
	OverprivilegedRoles int            `json:"overprivilegedRoles"`
	ProviderBreakdown   map[string]int `json:"providerBreakdown"`
}

type graphVisualization struct {
	Nodes []graphNode `json:"nodes"`
	Links []graphLink `json:"links"`
}

type graphNode struct {
	ID        string `json:"id"`
	Name      string `json:"name"`
	Type      string `json:"type"`
	Namespace string `json:"namespace"`
	Severity  string `json:"severity"`
	Group     int    `json:"group"`
}

type graphLink struct {
	Source string `json:"source"`
	Target string `json:"target"`
	Type   string `json:"type"`
	Label  string `json:"label"`
}

func (d *Dashboard) buildDashboardData(data DashboardData) dashboardJSON {
	result := dashboardJSON{}

	// Build summary
	criticalCount := 0
	highCount := 0
	mediumCount := 0
	lowCount := 0
	namespaceBreakdown := make(map[string]int)
	severityBreakdown := make(map[string]int)

	// Count from blast results
	for _, br := range data.BlastResults {
		switch br.MaxSeverity {
		case graph.SeverityCritical:
			criticalCount++
			severityBreakdown["critical"]++
		case graph.SeverityHigh:
			highCount++
			severityBreakdown["high"]++
		case graph.SeverityMedium:
			mediumCount++
			severityBreakdown["medium"]++
		case graph.SeverityLow:
			lowCount++
			severityBreakdown["low"]++
		}
		if br.SourceWorkload != nil {
			namespaceBreakdown[br.SourceWorkload.Namespace]++
		}
	}

	// Add RBAC findings
	if data.RBACAudit != nil {
		criticalCount += data.RBACAudit.Summary.Critical
		highCount += data.RBACAudit.Summary.High
		mediumCount += data.RBACAudit.Summary.Medium
		lowCount += data.RBACAudit.Summary.Low
	}

	// Add pod security findings
	if data.PodSecurity != nil {
		criticalCount += data.PodSecurity.Summary.Critical
		highCount += data.PodSecurity.Summary.High
		mediumCount += data.PodSecurity.Summary.Medium
	}

	attackPathCount := 0
	for _, ap := range data.AttackPaths {
		attackPathCount += ap.TotalPaths
	}

	cloudRoleCount := 0
	for _, br := range data.BlastResults {
		cloudRoleCount += len(br.CloudRoles)
	}

	policyViolations := 0
	if data.NetworkPolicy != nil {
		policyViolations = data.NetworkPolicy.TotalFindings
	}

	workloadCount := 0
	saCount := 0
	roleCount := 0
	if data.GraphStats.NodeCounts != nil {
		workloadCount = data.GraphStats.NodeCounts[graph.NodeWorkload]
		saCount = data.GraphStats.NodeCounts[graph.NodeServiceAccount]
		roleCount = data.GraphStats.NodeCounts[graph.NodeRole]
	}

	result.Summary = summaryData{
		TotalWorkloads:     workloadCount,
		CriticalFindings:   criticalCount,
		HighFindings:       highCount,
		MediumFindings:     mediumCount,
		LowFindings:        lowCount,
		AttackPaths:        attackPathCount,
		CloudRoles:         cloudRoleCount,
		PolicyViolations:   policyViolations,
		ServiceAccounts:    saCount,
		Roles:              roleCount,
		NamespaceBreakdown: namespaceBreakdown,
		SeverityBreakdown:  severityBreakdown,
	}

	// Build blast radius data with full details
	for _, br := range data.BlastResults {
		item := blastResultItem{
			Severity:   string(br.MaxSeverity),
			K8sPerms:   br.TotalK8sPerms,
			CloudRoles: len(br.CloudRoles),
		}
		if br.SourceWorkload != nil {
			item.Workload = br.SourceWorkload.Name
			item.Namespace = br.SourceWorkload.Namespace
			item.Kind = br.SourceWorkload.Metadata.WorkloadKind
		}

		// Add identity (service account)
		if br.ServiceAccount != nil {
			idItem := identityItem{
				Name:           br.ServiceAccount.Name,
				Namespace:      br.ServiceAccount.Namespace,
				Type:           "ServiceAccount",
				HasCloudAccess: br.ServiceAccount.HasCloudIdentity(),
			}
			if br.ServiceAccount.Metadata.CloudRoleARN != "" {
				idItem.CloudRoleARN = br.ServiceAccount.Metadata.CloudRoleARN
			}
			item.Identities = append(item.Identities, idItem)
			item.ServiceAccount = br.ServiceAccount.Name
		}

		// Add K8s resources
		for _, res := range br.K8sResources {
			resItem := k8sResourceItem{
				Resource:  res.Resource.Name,
				Namespace: res.Resource.Namespace,
				Kind:      res.Resource.Metadata.ResourceKind,
				Verbs:     res.Resource.Metadata.Verbs,
				ViaRole:   res.ViaRole,
				Severity:  string(res.Severity),
			}
			item.K8sResources = append(item.K8sResources, resItem)
			if res.Severity == graph.SeverityCritical || res.Severity == graph.SeverityHigh {
				item.BlastRadius = append(item.BlastRadius, fmt.Sprintf("%s (%s)", res.Resource.Name, res.ViaRole))
			}
		}

		// Add cloud resources
		for _, cr := range br.CloudRoles {
			cloudItem := cloudResourceItem{
				Provider: cr.Provider,
				RoleARN:  cr.RoleARN,
				IsAdmin:  false,
			}
			for _, policy := range cr.Policies {
				if policy.IsAdmin {
					cloudItem.IsAdmin = true
				}
				cloudItem.PolicyARNs = append(cloudItem.PolicyARNs, policy.Name)
			}
			item.CloudResources = append(item.CloudResources, cloudItem)
		}

		// Add risk factors
		if br.TotalK8sPerms > 10 {
			item.RiskFactors = append(item.RiskFactors, "High number of K8s permissions")
		}
		if len(br.CloudRoles) > 0 {
			item.RiskFactors = append(item.RiskFactors, "Has cloud IAM access")
		}
		for _, cr := range br.CloudRoles {
			for _, policy := range cr.Policies {
				if policy.IsAdmin {
					item.RiskFactors = append(item.RiskFactors, "Has cloud admin access")
					break
				}
			}
		}

		result.BlastRadius.Results = append(result.BlastRadius.Results, item)
	}

	// Sort blast results by severity
	sort.Slice(result.BlastRadius.Results, func(i, j int) bool {
		return severityOrder(result.BlastRadius.Results[i].Severity) < severityOrder(result.BlastRadius.Results[j].Severity)
	})

	// Build attack paths data with full details
	apSummary := analysis.SummarizeAttackPaths(data.AttackPaths)
	result.AttackPaths.Summary = attackPathSummary{
		TotalPaths:    apSummary.TotalPaths,
		CriticalPaths: apSummary.CriticalPaths,
		HighPaths:     apSummary.HighPaths,
		CloudPaths:    apSummary.CloudPaths,
	}
	for _, ap := range data.AttackPaths {
		item := attackPathItem{
			PathCount:    ap.TotalPaths,
			Critical:     ap.CriticalPaths,
			High:         ap.HighPaths,
			AffectsCloud: ap.CanReachCloud,
			Objectives:   ap.UniqueObjectives,
		}
		if ap.SourceWorkload != nil {
			item.Workload = ap.SourceWorkload.Name
			item.Namespace = ap.SourceWorkload.Namespace
		}

		// Add detailed paths
		for _, path := range ap.Paths {
			pathDetail := attackPathDetail{
				RiskScore:   path.RiskScore,
				Severity:    string(path.MaxSeverity),
				Objective:   path.Objective,
				Mitigations: path.Mitigations,
			}

			// Collect unique MITRE tactics
			mitreSet := make(map[string]bool)
			for _, step := range path.Steps {
				target := ""
				if step.ToNode != nil {
					target = step.ToNode.Name
				}
				stepItem := attackStepItem{
					Order:       step.StepNumber,
					Action:      step.Action,
					Target:      target,
					Technique:   string(step.Technique),
					MitreID:     step.MitreID,
					Description: step.Description,
				}
				pathDetail.Steps = append(pathDetail.Steps, stepItem)
				if step.MitreID != "" {
					mitreSet[step.MitreID] = true
				}
			}
			for mitreID := range mitreSet {
				pathDetail.MitreTactics = append(pathDetail.MitreTactics, mitreID)
			}

			item.Paths = append(item.Paths, pathDetail)
		}

		result.AttackPaths.Results = append(result.AttackPaths.Results, item)
	}

	// Build RBAC audit data
	if data.RBACAudit != nil {
		result.RBACAudit.Summary = rbacSummary{
			TotalFindings: data.RBACAudit.TotalFindings,
			Critical:      data.RBACAudit.Summary.Critical,
			High:          data.RBACAudit.Summary.High,
			Medium:        data.RBACAudit.Summary.Medium,
			Low:           data.RBACAudit.Summary.Low,
		}
		for _, f := range data.RBACAudit.Findings {
			finding := rbacFinding{
				CheckID:     f.CheckID,
				CheckName:   f.Title,
				Severity:    string(f.Severity),
				Description: f.Description,
				Remediation: f.Remediation,
			}
			if len(f.Affected) > 0 {
				finding.Subject = f.Affected[0].Name
				finding.Namespace = f.Affected[0].Namespace
			}
			for _, aff := range f.Affected {
				finding.Affected = append(finding.Affected, affectedItem{
					Name:      aff.Name,
					Namespace: aff.Namespace,
					Kind:      aff.Kind,
					Details:   aff.Details,
				})
			}
			result.RBACAudit.Findings = append(result.RBACAudit.Findings, finding)
		}
	}

	// Build pod security data
	if data.PodSecurity != nil {
		result.PodSecurity.Summary = podSecSummary{
			TotalFindings: data.PodSecurity.TotalFindings,
			Critical:      data.PodSecurity.Summary.Critical,
			High:          data.PodSecurity.Summary.High,
			Medium:        data.PodSecurity.Summary.Medium,
			Low:           data.PodSecurity.Summary.Low,
		}
		for _, f := range data.PodSecurity.Findings {
			finding := podSecFinding{
				CheckID:     f.CheckID,
				CheckName:   f.Title,
				Severity:    string(f.Severity),
				Details:     f.Description,
				Remediation: f.Remediation,
			}
			if len(f.Affected) > 0 {
				finding.Workload = f.Affected[0].Name
				finding.Namespace = f.Affected[0].Namespace
				finding.Container = f.Affected[0].Container
				if f.Affected[0].Details != "" {
					finding.Details = f.Affected[0].Details
				}
			}
			for _, aff := range f.Affected {
				finding.Affected = append(finding.Affected, affectedItem{
					Name:      aff.Name,
					Namespace: aff.Namespace,
					Kind:      aff.Container,
					Details:   aff.Details,
				})
			}
			result.PodSecurity.Findings = append(result.PodSecurity.Findings, finding)
		}
	}

	// Build network policy data
	if data.NetworkPolicy != nil {
		result.NetworkPolicy.Summary = netPolSummary{
			TotalFindings:   data.NetworkPolicy.TotalFindings,
			WorkloadsNoPol:  data.NetworkPolicy.Summary.WorkloadsWithoutPolicy,
			ExternalExposed: data.NetworkPolicy.Summary.WorkloadsExternallyExposed,
		}
		for _, f := range data.NetworkPolicy.Findings {
			finding := netPolFinding{
				CheckID:   f.CheckID,
				CheckName: f.Title,
				Severity:  string(f.Severity),
				Details:   f.Description,
			}
			if len(f.Affected) > 0 {
				finding.Workload = f.Affected[0].Name
				finding.Namespace = f.Affected[0].Namespace
				if f.Affected[0].Details != "" {
					finding.Details = f.Affected[0].Details
				}
			}
			for _, aff := range f.Affected {
				finding.Affected = append(finding.Affected, affectedItem{
					Name:      aff.Name,
					Namespace: aff.Namespace,
					Details:   aff.Details,
				})
			}
			result.NetworkPolicy.Findings = append(result.NetworkPolicy.Findings, finding)
		}
		for _, s := range data.NetworkPolicy.SuggestedPolicies {
			result.NetworkPolicy.Suggestions = append(result.NetworkPolicy.Suggestions, suggestedPolicy{
				Workload:     s.Workload,
				WorkloadKind: s.WorkloadKind,
				Namespace:    s.Namespace,
				PolicyName:   s.PolicyName,
				YAML:         s.YAML,
				Description:  s.Description,
				Services:     s.Services,
			})
		}
	}

	// Build cloud audit data
	if data.CloudAudit != nil {
		providerBreakdown := make(map[string]int)
		adminRoles := 0
		overprivileged := 0
		for _, f := range data.CloudAudit.Findings {
			if f.Category == analysis.CloudCategoryAdminAccess {
				adminRoles++
			}
			if f.Severity == graph.SeverityCritical || f.Severity == graph.SeverityHigh {
				overprivileged++
			}
			providerBreakdown[f.Provider]++
		}
		result.CloudAudit.Summary = cloudSummary{
			TotalRoles:          data.CloudAudit.AnalyzedRoles,
			AdminRoles:          adminRoles,
			OverprivilegedRoles: overprivileged,
			ProviderBreakdown:   providerBreakdown,
		}
		for _, f := range data.CloudAudit.Findings {
			finding := cloudFinding{
				Severity:    string(f.Severity),
				RoleARN:     f.RoleARN,
				Provider:    f.Provider,
				Issue:       f.Title,
				Description: f.Description,
			}
			result.CloudAudit.Findings = append(result.CloudAudit.Findings, finding)
		}
	}

	// Build graph visualization data
	if data.Graph != nil {
		nodeSet := make(map[string]bool)

		// Add nodes for blast results
		for _, br := range data.BlastResults {
			if br.SourceWorkload != nil {
				node := graphNode{
					ID:        br.SourceWorkload.ID,
					Name:      br.SourceWorkload.Name,
					Type:      "workload",
					Namespace: br.SourceWorkload.Namespace,
					Severity:  string(br.MaxSeverity),
					Group:     1,
				}
				if !nodeSet[node.ID] {
					result.GraphData.Nodes = append(result.GraphData.Nodes, node)
					nodeSet[node.ID] = true
				}
			}

			if br.ServiceAccount != nil {
				node := graphNode{
					ID:        br.ServiceAccount.ID,
					Name:      br.ServiceAccount.Name,
					Type:      "service_account",
					Namespace: br.ServiceAccount.Namespace,
					Group:     2,
				}
				if !nodeSet[node.ID] {
					result.GraphData.Nodes = append(result.GraphData.Nodes, node)
					nodeSet[node.ID] = true
				}
				if br.SourceWorkload != nil {
					result.GraphData.Links = append(result.GraphData.Links, graphLink{
						Source: br.SourceWorkload.ID,
						Target: br.ServiceAccount.ID,
						Type:   "uses",
						Label:  "uses",
					})
				}
			}

			for _, cr := range br.CloudRoles {
				if cr.CloudRole == nil {
					continue
				}
				node := graphNode{
					ID:        cr.CloudRole.ID,
					Name:      cr.CloudRole.Name,
					Type:      "cloud_role",
					Namespace: "",
					Group:     3,
				}
				if !nodeSet[node.ID] {
					result.GraphData.Nodes = append(result.GraphData.Nodes, node)
					nodeSet[node.ID] = true
				}
			}
		}
	}

	// Build permissions data
	if data.Permissions != nil {
		// Convert WhoCan results to JSON format
		convertWhoCan := func(results []*analysis.WhoCanResult) []whoCanResultJSON {
			var out []whoCanResultJSON
			for _, r := range results {
				item := whoCanResultJSON{
					Verb:       r.Verb,
					Resource:   r.Resource,
					Namespace:  r.Namespace,
					TotalCount: r.TotalCount,
				}
				for _, s := range r.Subjects {
					item.Subjects = append(item.Subjects, subjectJSON{
						Kind:      s.Kind,
						Name:      s.Name,
						Namespace: s.Namespace,
						ViaRole:   s.ViaRole,
					})
				}
				out = append(out, item)
			}
			return out
		}

		result.Permissions.SecretAccess = convertWhoCan(data.Permissions.SecretAccess)
		result.Permissions.PodExec = convertWhoCan(data.Permissions.PodExec)
		result.Permissions.PodCreate = convertWhoCan(data.Permissions.PodCreate)
		result.Permissions.PodDelete = convertWhoCan(data.Permissions.PodDelete)
		result.Permissions.ClusterAdmin = convertWhoCan(data.Permissions.ClusterAdmin)
		result.Permissions.RoleBindings = convertWhoCan(data.Permissions.RoleBindings)
		result.Permissions.Impersonate = convertWhoCan(data.Permissions.Impersonate)

		// Convert dangerous permissions
		for _, dp := range data.Permissions.DangerousPerms {
			result.Permissions.DangerousPerms = append(result.Permissions.DangerousPerms, dangerousPermJSON{
				Subject:     dp.Subject,
				SubjectKind: dp.SubjectKind,
				Namespace:   dp.Namespace,
				Permission:  dp.Permission,
				Severity:    dp.Severity,
				Details:     dp.Details,
			})
		}

		// Build summary
		critCount := 0
		highCount := 0
		secretAccessors := 0
		podExecUsers := 0
		clusterAdmins := 0

		for _, dp := range data.Permissions.DangerousPerms {
			if dp.Severity == "critical" {
				critCount++
			} else if dp.Severity == "high" {
				highCount++
			}
		}
		for _, r := range data.Permissions.SecretAccess {
			secretAccessors += len(r.Subjects)
		}
		for _, r := range data.Permissions.PodExec {
			podExecUsers += len(r.Subjects)
		}
		for _, r := range data.Permissions.ClusterAdmin {
			clusterAdmins += len(r.Subjects)
		}

		result.Permissions.Summary = permissionsSummary{
			TotalDangerous:  len(data.Permissions.DangerousPerms),
			CriticalCount:   critCount,
			HighCount:       highCount,
			SecretAccessors: secretAccessors,
			PodExecUsers:    podExecUsers,
			ClusterAdmins:   clusterAdmins,
		}
	}

	return result
}

func severityOrder(s string) int {
	switch strings.ToLower(s) {
	case "critical":
		return 0
	case "high":
		return 1
	case "medium":
		return 2
	case "low":
		return 3
	default:
		return 4
	}
}

const dashboardHTMLTemplate = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>Security Dashboard - Identity Chain</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <link href="https://fonts.googleapis.com/css2?family=Inter:wght@400;500;600;700;800;900&display=swap" rel="stylesheet">
  <style>
    :root {
      --bg-primary: #0d1117;
      --bg-secondary: #161b22;
      --bg-card: rgba(22, 27, 34, 0.95);
      --bg-card-hover: rgba(30, 37, 46, 0.95);
      --border-subtle: rgba(48, 54, 61, 0.8);
      --border-hover: rgba(88, 96, 105, 0.8);
      --text-primary: #f0f6fc;
      --text-secondary: #8b949e;
      --text-muted: #6e7681;
      --accent-blue: #58a6ff;
      --accent-purple: #a371f7;
      --accent-cyan: #39d4ff;
      --accent-gradient: linear-gradient(135deg, #58a6ff, #a371f7);
      --critical: #f85149;
      --critical-glow: rgba(248, 81, 73, 0.4);
      --high: #f0883e;
      --high-glow: rgba(240, 136, 62, 0.4);
      --medium: #d29922;
      --medium-glow: rgba(210, 153, 34, 0.4);
      --low: #3fb950;
      --low-glow: rgba(63, 185, 80, 0.4);
      --glass: rgba(255, 255, 255, 0.02);
      --shadow-sm: 0 1px 3px rgba(0, 0, 0, 0.4);
      --shadow-md: 0 4px 20px rgba(0, 0, 0, 0.5);
      --shadow-lg: 0 12px 50px rgba(0, 0, 0, 0.6);
      --shadow-glow-blue: 0 0 30px rgba(88, 166, 255, 0.3);
      --shadow-glow-purple: 0 0 30px rgba(163, 113, 247, 0.3);
      --radius-sm: 8px;
      --radius-md: 12px;
      --radius-lg: 16px;
      --radius-xl: 20px;
      --transition-fast: 0.15s cubic-bezier(0.4, 0, 0.2, 1);
      --transition-smooth: 0.3s cubic-bezier(0.4, 0, 0.2, 1);
      --transition-bounce: 0.5s cubic-bezier(0.34, 1.56, 0.64, 1);
    }

    * { box-sizing: border-box; margin: 0; padding: 0; }
    html { scroll-behavior: smooth; }

    body {
      font-family: 'Inter', -apple-system, BlinkMacSystemFont, sans-serif;
      background: var(--bg-primary);
      color: var(--text-primary);
      min-height: 100vh;
      line-height: 1.6;
      -webkit-font-smoothing: antialiased;
      -moz-osx-font-smoothing: grayscale;
    }

    /* Animated background with multiple glows */
    body::before {
      content: '';
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background:
        radial-gradient(ellipse 100%% 80%% at 20%% -30%%, rgba(88, 166, 255, 0.12), transparent 50%%),
        radial-gradient(ellipse 80%% 60%% at 80%% 20%%, rgba(163, 113, 247, 0.1), transparent 50%%),
        radial-gradient(ellipse 60%% 50%% at 60%% 80%%, rgba(57, 212, 255, 0.05), transparent 50%%);
      pointer-events: none;
      z-index: -1;
    }

    /* Header with Logo */
    .header {
      padding: 20px 48px;
      display: flex;
      justify-content: space-between;
      align-items: center;
      border-bottom: 1px solid var(--border-subtle);
      backdrop-filter: blur(20px);
      background: rgba(13, 17, 23, 0.9);
      position: sticky;
      top: 0;
      z-index: 100;
    }

    .header-left { display: flex; align-items: center; gap: 16px; }

    .logo-container {
      display: flex;
      align-items: center;
      gap: 14px;
    }

    .logo-icon {
      height: 120px;
      position: relative;
    }

    .logo-icon img { height: 100%%; width: auto; border-radius: 12px; }

    .header-actions { display: flex; gap: 10px; }

    .header-btn {
      background: rgba(88, 166, 255, 0.1);
      border: 1px solid rgba(88, 166, 255, 0.3);
      border-radius: var(--radius-md);
      padding: 10px 18px;
      color: var(--accent-blue);
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all var(--transition-smooth);
      display: flex;
      align-items: center;
      gap: 6px;
    }

    .header-btn:hover {
      background: rgba(88, 166, 255, 0.2);
      border-color: var(--accent-blue);
      transform: translateY(-2px);
      box-shadow: 0 4px 15px rgba(88, 166, 255, 0.25);
    }

    .header-btn.secondary {
      background: var(--glass);
      border: 1px solid var(--border-subtle);
      color: var(--text-secondary);
    }

    .header-btn.secondary:hover {
      background: var(--bg-card-hover);
      border-color: var(--border-hover);
      color: var(--text-primary);
      box-shadow: none;
    }

    .container { max-width: 1600px; margin: 0 auto; padding: 32px 48px; }

    /* Stats Row - Colorful Cards with Glow */
    .stats-row {
      display: grid;
      grid-template-columns: repeat(6, 1fr);
      gap: 16px;
      margin-bottom: 32px;
    }

    .stat-card {
      background: var(--bg-card);
      border-radius: var(--radius-xl);
      padding: 24px 20px;
      text-align: center;
      cursor: pointer;
      transition: all var(--transition-smooth);
      position: relative;
      overflow: hidden;
    }

    .stat-card::before {
      content: '';
      position: absolute;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      border-radius: var(--radius-xl);
      padding: 2px;
      background: linear-gradient(135deg, transparent 30%%, var(--card-glow-color, rgba(88,166,255,0.3)) 50%%, transparent 70%%);
      -webkit-mask: linear-gradient(#fff 0 0) content-box, linear-gradient(#fff 0 0);
      -webkit-mask-composite: xor;
      mask-composite: exclude;
      opacity: 0.6;
      transition: opacity var(--transition-smooth);
    }

    .stat-card:hover {
      transform: translateY(-6px) scale(1.02);
      box-shadow: 0 20px 40px rgba(0, 0, 0, 0.4);
    }

    .stat-card:hover::before { opacity: 1; }

    .stat-card.workloads { --card-glow-color: rgba(88, 166, 255, 0.5); }
    .stat-card.critical { --card-glow-color: rgba(248, 81, 73, 0.5); }
    .stat-card.high { --card-glow-color: rgba(240, 136, 62, 0.5); }
    .stat-card.paths { --card-glow-color: rgba(163, 113, 247, 0.5); }
    .stat-card.cloud { --card-glow-color: rgba(57, 212, 255, 0.5); }
    .stat-card.policy { --card-glow-color: rgba(210, 153, 34, 0.5); }

    .stat-value {
      font-size: 42px;
      font-weight: 800;
      letter-spacing: -2px;
      line-height: 1;
      transition: transform var(--transition-bounce);
    }

    .stat-card:hover .stat-value { transform: scale(1.08); }

    .stat-value.workloads { color: var(--accent-blue); text-shadow: 0 0 30px rgba(88, 166, 255, 0.5); }
    .stat-value.critical { color: var(--critical); text-shadow: 0 0 30px rgba(248, 81, 73, 0.5); }
    .stat-value.high { color: var(--high); text-shadow: 0 0 30px rgba(240, 136, 62, 0.5); }
    .stat-value.paths { color: var(--accent-purple); text-shadow: 0 0 30px rgba(163, 113, 247, 0.5); }
    .stat-value.cloud { color: var(--accent-cyan); text-shadow: 0 0 30px rgba(57, 212, 255, 0.5); }
    .stat-value.policy { color: var(--medium); text-shadow: 0 0 30px rgba(210, 153, 34, 0.5); }

    .stat-label {
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1.5px;
      margin-top: 10px;
      font-weight: 600;
    }

    /* Tabs - Pill Style */
    .tabs {
      display: flex;
      gap: 4px;
      margin-bottom: 28px;
      background: var(--bg-card);
      padding: 5px;
      border-radius: var(--radius-lg);
      border: 1px solid var(--border-subtle);
      overflow-x: auto;
    }

    .tab {
      flex: 1;
      padding: 12px 20px;
      background: transparent;
      border: none;
      border-radius: var(--radius-md);
      color: var(--text-muted);
      cursor: pointer;
      font-size: 13px;
      font-weight: 600;
      transition: all var(--transition-smooth);
      white-space: nowrap;
    }

    .tab:hover {
      color: var(--text-secondary);
      background: rgba(255, 255, 255, 0.03);
    }

    .tab.active {
      background: var(--accent-gradient);
      color: #fff;
      box-shadow: 0 4px 15px rgba(88, 166, 255, 0.35);
    }

    .panel { display: none; animation: fadeIn 0.3s ease; }
    .panel.active { display: block; }

    @keyframes fadeIn {
      from { opacity: 0; transform: translateY(10px); }
      to { opacity: 1; transform: translateY(0); }
    }

    @keyframes pulse {
      0%%, 100%% { opacity: 1; }
      50%% { opacity: 0.6; }
    }

    /* Section Headers */
    .section-header {
      display: flex;
      align-items: center;
      justify-content: space-between;
      margin-bottom: 24px;
    }

    .section-title {
      font-size: 28px;
      font-weight: 800;
      color: var(--text-primary);
      letter-spacing: -0.5px;
    }

    /* Findings Grid */
    .findings-grid { display: grid; gap: 16px; }

    .finding-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-lg);
      padding: 20px 24px;
      cursor: pointer;
      transition: all var(--transition-smooth);
      backdrop-filter: blur(20px);
      position: relative;
    }

    .finding-card:hover {
      border-color: var(--border-hover);
      transform: translateY(-2px);
      box-shadow: var(--shadow-md);
    }

    .finding-card.critical { border-left: 4px solid var(--critical); }
    .finding-card.high { border-left: 4px solid var(--high); }
    .finding-card.medium { border-left: 4px solid var(--medium); }
    .finding-card.low { border-left: 4px solid var(--low); }

    .finding-header { display: flex; align-items: flex-start; gap: 16px; }

    .finding-severity {
      padding: 6px 14px;
      border-radius: var(--radius-sm);
      font-size: 11px;
      font-weight: 700;
      text-transform: uppercase;
      letter-spacing: 0.5px;
    }

    .finding-severity.critical { background: rgba(239, 68, 68, 0.15); color: var(--critical); }
    .finding-severity.high { background: rgba(249, 115, 22, 0.15); color: var(--high); }
    .finding-severity.medium { background: rgba(234, 179, 8, 0.15); color: var(--medium); }
    .finding-severity.low { background: rgba(34, 197, 94, 0.15); color: var(--low); }
    .finding-severity.workloads { background: rgba(59, 130, 246, 0.15); color: var(--accent-blue); }

    .finding-content { flex: 1; min-width: 0; }
    .finding-title { font-size: 15px; font-weight: 600; color: var(--text-primary); margin-bottom: 6px; }
    .finding-meta { font-size: 13px; color: var(--text-muted); margin-bottom: 8px; }
    .finding-desc { font-size: 14px; color: var(--text-secondary); line-height: 1.6; }

    /* Cards */
    .stat-card, .chart-card, .risk-card {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-xl);
      backdrop-filter: blur(20px);
      transition: all var(--transition-smooth);
    }

    /* Mini Badges */
    .mini-badge {
      display: inline-block;
      padding: 4px 12px;
      border-radius: var(--radius-sm);
      font-size: 11px;
      font-weight: 600;
      letter-spacing: 0.3px;
    }

    .mini-badge.critical { background: rgba(239, 68, 68, 0.15); color: var(--critical); }
    .mini-badge.high { background: rgba(249, 115, 22, 0.15); color: var(--high); }
    .mini-badge.medium { background: rgba(234, 179, 8, 0.15); color: var(--medium); }
    .mini-badge.low { background: rgba(34, 197, 94, 0.15); color: var(--low); }
    .mini-badge.cloud { background: rgba(6, 182, 212, 0.15); color: #06b6d4; }

    /* Charts */
    .chart-row { display: grid; grid-template-columns: repeat(3, 1fr); gap: 24px; margin-bottom: 32px; }
    .chart-card { padding: 24px; }
    .chart-title { font-size: 13px; font-weight: 700; color: var(--text-muted); margin-bottom: 20px; text-transform: uppercase; letter-spacing: 1px; }
    .chart-container { height: 200px; display: flex; align-items: center; justify-content: center; }

    /* Graph */
    .graph-container {
      background: var(--bg-secondary);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-xl);
      height: 500px;
      margin-bottom: 32px;
      position: relative;
      overflow: hidden;
    }

    .graph-controls { position: absolute; top: 20px; right: 20px; display: flex; gap: 8px; z-index: 10; }
    .graph-btn {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 8px 14px;
      color: var(--text-secondary);
      cursor: pointer;
      font-size: 12px;
      font-weight: 500;
      transition: all var(--transition-fast);
    }
    .graph-btn:hover { background: var(--bg-card-hover); color: var(--text-primary); }

    .graph-legend {
      position: absolute;
      bottom: 20px;
      left: 20px;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 16px 20px;
      backdrop-filter: blur(20px);
    }
    .legend-item { display: flex; align-items: center; gap: 10px; font-size: 12px; color: var(--text-secondary); margin-bottom: 8px; }
    .legend-item:last-child { margin-bottom: 0; }
    .legend-dot { width: 10px; height: 10px; border-radius: 50%%; }

    /* Modal */
    .modal-overlay {
      position: fixed;
      top: 0;
      left: 0;
      right: 0;
      bottom: 0;
      background: rgba(0, 0, 0, 0.8);
      backdrop-filter: blur(8px);
      display: none;
      align-items: center;
      justify-content: center;
      z-index: 1000;
      animation: fadeIn 0.2s ease;
    }
    .modal-overlay.active { display: flex; }

    .modal {
      background: var(--bg-secondary);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-xl);
      width: 90%%;
      max-width: 900px;
      max-height: 85vh;
      overflow: hidden;
      box-shadow: var(--shadow-lg);
      animation: modalSlide 0.3s ease;
    }

    @keyframes modalSlide {
      from { opacity: 0; transform: scale(0.95) translateY(20px); }
      to { opacity: 1; transform: scale(1) translateY(0); }
    }

    .modal-header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      padding: 24px 28px;
      border-bottom: 1px solid var(--border-subtle);
      background: linear-gradient(180deg, rgba(255,255,255,0.03), transparent);
    }
    .modal-title { font-size: 20px; font-weight: 700; }
    .modal-close {
      background: rgba(239, 68, 68, 0.1);
      border: none;
      width: 36px;
      height: 36px;
      border-radius: var(--radius-sm);
      color: var(--critical);
      cursor: pointer;
      font-size: 20px;
      transition: all var(--transition-fast);
    }
    .modal-close:hover { background: rgba(239, 68, 68, 0.2); }
    .modal-body { padding: 28px; overflow-y: auto; max-height: calc(85vh - 80px); }

    .modal-section { margin-bottom: 28px; }
    .modal-section:last-child { margin-bottom: 0; }
    .modal-section-title {
      font-size: 11px;
      font-weight: 700;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1.5px;
      margin-bottom: 16px;
    }

    .modal-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 16px; }
    .modal-stat { background: var(--bg-card); border: 1px solid var(--border-subtle); border-radius: var(--radius-md); padding: 20px; }
    .modal-stat-value { font-size: 32px; font-weight: 800; letter-spacing: -1px; }
    .modal-stat-label { font-size: 12px; color: var(--text-muted); margin-top: 6px; }

    .modal-list { list-style: none; }
    .modal-list li {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      padding: 16px 20px;
      margin-bottom: 10px;
      transition: all var(--transition-fast);
    }
    .modal-list li:hover { border-color: var(--border-hover); }
    .modal-list li:last-child { margin-bottom: 0; }
    .modal-list-title { font-weight: 600; font-size: 14px; }
    .modal-list-meta { font-size: 12px; color: var(--text-muted); margin-top: 4px; }

    .attack-step {
      display: flex;
      gap: 16px;
      padding: 20px;
      background: var(--bg-card);
      border-radius: var(--radius-md);
      margin-bottom: 12px;
      border-left: 3px solid var(--accent-blue);
    }
    .step-number {
      width: 32px;
      height: 32px;
      background: var(--accent-gradient);
      border-radius: 50%%;
      display: flex;
      align-items: center;
      justify-content: center;
      font-size: 13px;
      font-weight: 700;
    }
    .step-content { flex: 1; }
    .step-action { font-weight: 600; font-size: 14px; }
    .step-target { font-size: 13px; color: var(--text-secondary); margin-top: 4px; }
    .step-mitre {
      background: rgba(139, 92, 246, 0.15);
      color: var(--accent-purple);
      padding: 3px 10px;
      border-radius: 4px;
      font-size: 10px;
      font-weight: 600;
      font-family: monospace;
      margin-left: 8px;
    }

    .risk-meter { height: 6px; background: var(--border-subtle); border-radius: 3px; overflow: hidden; margin-top: 12px; }
    .risk-meter-fill { height: 100%%; border-radius: 3px; transition: width 0.6s cubic-bezier(0.4, 0, 0.2, 1); }
    .risk-meter-fill.critical { background: linear-gradient(90deg, var(--critical), #dc2626); }
    .risk-meter-fill.high { background: linear-gradient(90deg, var(--high), #ea580c); }
    .risk-meter-fill.medium { background: linear-gradient(90deg, var(--medium), #ca8a04); }
    .risk-meter-fill.low { background: linear-gradient(90deg, var(--low), #16a34a); }

    .top-risks { display: grid; grid-template-columns: repeat(2, 1fr); gap: 20px; }
    .risk-card { padding: 24px; cursor: pointer; }
    .risk-card:hover { transform: translateY(-3px); box-shadow: var(--shadow-md); border-color: var(--border-hover); }
    .risk-card-header { display: flex; justify-content: space-between; align-items: flex-start; margin-bottom: 12px; }
    .risk-card-title { font-weight: 600; font-size: 15px; }
    .risk-card-type { font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1px; margin-top: 4px; }
    .risk-card-desc { font-size: 14px; color: var(--text-secondary); line-height: 1.6; }

    .empty-state { text-align: center; padding: 80px 20px; color: var(--text-muted); }
    .empty-title { font-size: 18px; font-weight: 600; color: var(--text-secondary); }

    .workload-row {
      display: grid;
      grid-template-columns: 2fr 1fr 1fr 1fr 100px;
      gap: 16px;
      padding: 18px 24px;
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-md);
      margin-bottom: 10px;
      align-items: center;
      cursor: pointer;
      transition: all var(--transition-smooth);
    }
    .workload-row:hover { border-color: var(--border-hover); transform: translateY(-2px); box-shadow: var(--shadow-sm); }
    .workload-name { font-weight: 600; }
    .workload-ns { font-size: 12px; color: var(--text-muted); margin-top: 2px; }

    .table-header {
      display: grid;
      grid-template-columns: 2fr 1fr 1fr 1fr 100px;
      gap: 16px;
      padding: 14px 24px;
      font-size: 11px;
      color: var(--text-muted);
      text-transform: uppercase;
      letter-spacing: 1.5px;
      font-weight: 600;
    }

    .filters { display: flex; gap: 10px; flex-wrap: wrap; }
    .filter-btn {
      background: var(--bg-card);
      border: 1px solid var(--border-subtle);
      border-radius: var(--radius-sm);
      padding: 10px 18px;
      color: var(--text-muted);
      cursor: pointer;
      font-size: 12px;
      font-weight: 600;
      transition: all var(--transition-fast);
    }
    .filter-btn:hover { background: var(--bg-card-hover); border-color: var(--border-hover); color: var(--text-secondary); }
    .filter-btn.active { background: var(--accent-gradient); border-color: transparent; color: #fff; }

    .remediation-box {
      background: rgba(34, 197, 94, 0.08);
      border: 1px solid rgba(34, 197, 94, 0.2);
      border-radius: var(--radius-md);
      padding: 16px 20px;
      font-size: 14px;
      color: var(--low);
    }

    .finding-details { display: none; margin-top: 20px; padding-top: 20px; border-top: 1px solid var(--border-subtle); }
    .finding-details.expanded { display: block; }
    .detail-section { margin-bottom: 20px; }
    .detail-label { font-size: 11px; font-weight: 700; color: var(--text-muted); text-transform: uppercase; letter-spacing: 1.5px; margin-bottom: 10px; }
    .detail-list { list-style: none; }
    .detail-list li { font-size: 13px; color: var(--text-secondary); padding: 8px 0; border-bottom: 1px solid var(--border-subtle); display: flex; justify-content: space-between; }
    .detail-list li:last-child { border-bottom: none; }

    /* Scrollbar styling */
    ::-webkit-scrollbar { width: 8px; height: 8px; }
    ::-webkit-scrollbar-track { background: var(--bg-secondary); }
    ::-webkit-scrollbar-thumb { background: var(--border-hover); border-radius: 4px; }
    ::-webkit-scrollbar-thumb:hover { background: rgba(255, 255, 255, 0.2); }

    @media (max-width: 1200px) {
      .stats-row { grid-template-columns: repeat(3, 1fr); }
      .chart-row { grid-template-columns: repeat(2, 1fr); }
      .container { padding: 32px; }
    }
    @media (max-width: 768px) {
      .stats-row { grid-template-columns: repeat(2, 1fr); }
      .tabs { flex-wrap: wrap; }
      .chart-row { grid-template-columns: 1fr; }
      .top-risks { grid-template-columns: 1fr; }
      .modal-grid { grid-template-columns: 1fr; }
      .header { padding: 20px 24px; flex-direction: column; gap: 16px; }
      .container { padding: 20px; }
    }
  </style>
</head>
<body>
  <div class="header">
    <div class="header-left">
      <div class="logo-container">
        <div class="logo-icon">
          <img src="data:image/png;base64,%s" alt="Identity Chain"/>
        </div>
      </div>
    </div>
    <div class="header-actions">
      <button class="header-btn" onclick="exportReport()">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 0a8 8 0 110 16A8 8 0 018 0zm0 1.5a6.5 6.5 0 100 13 6.5 6.5 0 000-13zM8 9.5l3-3h-2V4H7v2.5H5l3 3z"/></svg>
        Export Report
      </button>
      <button class="header-btn secondary" onclick="location.reload()">
        <svg width="16" height="16" viewBox="0 0 16 16" fill="currentColor"><path d="M8 3a5 5 0 104.546 2.914.75.75 0 011.352-.65A6.5 6.5 0 118 1.5V0l3 2.5-3 2.5V3z"/></svg>
        Refresh
      </button>
    </div>
  </div>

  <div class="container">
    <div class="stats-row">
      <div class="stat-card workloads" onclick="showPanel('blast')">
        <div class="stat-value workloads">%d</div>
        <div class="stat-label">Workloads</div>
      </div>
      <div class="stat-card critical" onclick="filterBySeverity('critical')">
        <div class="stat-value critical">%d</div>
        <div class="stat-label">Critical</div>
      </div>
      <div class="stat-card high" onclick="filterBySeverity('high')">
        <div class="stat-value high">%d</div>
        <div class="stat-label">High Risk</div>
      </div>
      <div class="stat-card paths" onclick="showPanel('attack')">
        <div class="stat-value paths">%d</div>
        <div class="stat-label">Attack Paths</div>
      </div>
      <div class="stat-card cloud" onclick="showPanel('cloud')">
        <div class="stat-value cloud">%d</div>
        <div class="stat-label">Cloud Roles</div>
      </div>
      <div class="stat-card policy" onclick="showPanel('netpol')">
        <div class="stat-value policy">%d</div>
        <div class="stat-label">Policy Violations</div>
      </div>
    </div>

    <div class="tabs">
      <button class="tab active" data-panel="overview" onclick="showPanel('overview')">Overview</button>
      <button class="tab" data-panel="blast" onclick="showPanel('blast')">Blast Radius</button>
      <button class="tab" data-panel="attack" onclick="showPanel('attack')">Attack Paths</button>
      <button class="tab" data-panel="permissions" onclick="showPanel('permissions')">Permissions</button>
      <button class="tab" data-panel="rbac" onclick="showPanel('rbac')">RBAC Audit</button>
      <button class="tab" data-panel="podsec" onclick="showPanel('podsec')">Pod Security</button>
      <button class="tab" data-panel="netpol" onclick="showPanel('netpol')">Network Policy</button>
      <button class="tab" data-panel="cloud" onclick="showPanel('cloud')">Cloud IAM</button>
    </div>

    <div id="panel-overview" class="panel active"></div>
    <div id="panel-blast" class="panel"></div>
    <div id="panel-attack" class="panel"></div>
    <div id="panel-permissions" class="panel"></div>
    <div id="panel-rbac" class="panel"></div>
    <div id="panel-podsec" class="panel"></div>
    <div id="panel-netpol" class="panel"></div>
    <div id="panel-cloud" class="panel"></div>
  </div>

  <!-- Modal -->
  <div class="modal-overlay" id="modal-overlay" onclick="closeModal(event)">
    <div class="modal" onclick="event.stopPropagation()">
      <div class="modal-header">
        <div class="modal-title" id="modal-title">Details</div>
        <button class="modal-close" onclick="closeModal()">&times;</button>
      </div>
      <div class="modal-body" id="modal-body"></div>
    </div>
  </div>

  <script>
const data = %s;
let currentFilter = 'all';

function showPanel(name) {
  document.querySelectorAll('.panel').forEach(p => p.classList.remove('active'));
  document.querySelectorAll('.tab').forEach(t => t.classList.remove('active'));
  document.getElementById('panel-' + name).classList.add('active');
  document.querySelector('.tab[data-panel="' + name + '"]').classList.add('active');
}

function filterBySeverity(severity) {
  currentFilter = severity;
  showPanel('overview');
  renderOverview();
}

function openModal(title, content) {
  document.getElementById('modal-title').textContent = title;
  document.getElementById('modal-body').innerHTML = content;
  document.getElementById('modal-overlay').classList.add('active');
}

function closeModal(event) {
  if (!event || event.target === document.getElementById('modal-overlay')) {
    document.getElementById('modal-overlay').classList.remove('active');
  }
}

function exportReport() {
  const blob = new Blob([JSON.stringify(data, null, 2)], {type: 'application/json'});
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = 'security-report-' + new Date().toISOString().split('T')[0] + '.json';
  a.click();
}

function renderSeverityChart(containerId, chartData) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const width = 180;
  const height = 180;
  const radius = Math.min(width, height) / 2 - 10;

  const color = d3.scaleOrdinal()
    .domain(['critical', 'high', 'medium', 'low'])
    .range(['#ef4444', '#f97316', '#eab308', '#22c55e']);

  const pie = d3.pie().value(d => d.value).sort(null);
  const arc = d3.arc().innerRadius(radius * 0.6).outerRadius(radius);

  const svg = d3.select(container)
    .append('svg')
    .attr('width', width)
    .attr('height', height)
    .append('g')
    .attr('transform', 'translate(' + width/2 + ',' + height/2 + ')');

  const pieData = Object.entries(chartData).map(([key, value]) => ({name: key, value: value})).filter(d => d.value > 0);

  if (pieData.length === 0) {
    svg.append('text')
      .attr('text-anchor', 'middle')
      .attr('dy', '.35em')
      .attr('fill', '#64748b')
      .text('No data');
    return;
  }

  svg.selectAll('path')
    .data(pie(pieData))
    .enter()
    .append('path')
    .attr('d', arc)
    .attr('fill', d => color(d.data.name))
    .attr('stroke', '#1e293b')
    .attr('stroke-width', 2);

  // Center text
  const total = pieData.reduce((sum, d) => sum + d.value, 0);
  svg.append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', '-0.2em')
    .attr('fill', '#f1f5f9')
    .attr('font-size', '24px')
    .attr('font-weight', '700')
    .text(total);
  svg.append('text')
    .attr('text-anchor', 'middle')
    .attr('dy', '1.2em')
    .attr('fill', '#64748b')
    .attr('font-size', '11px')
    .text('TOTAL');
}

function renderOverview() {
  let html = '';

  // Charts row
  html += '<div class="chart-row">';
  html += '<div class="chart-card"><div class="chart-title">Severity Distribution</div><div class="chart-container" id="severity-chart"></div></div>';
  html += '<div class="chart-card"><div class="chart-title">Category Breakdown</div><div class="chart-container" id="category-chart"></div></div>';
  html += '<div class="chart-card"><div class="chart-title">Risk Score</div><div class="chart-container" id="risk-chart"></div></div>';
  html += '</div>';

  // Top risks section
  html += '<div class="section-header"><div class="section-title">Top Security Risks</div>';
  html += '<div class="filters">';
  html += '<button class="filter-btn ' + (currentFilter === 'all' ? 'active' : '') + '" onclick="currentFilter=\'all\';renderOverview()">All</button>';
  html += '<button class="filter-btn ' + (currentFilter === 'critical' ? 'active' : '') + '" onclick="currentFilter=\'critical\';renderOverview()">Critical</button>';
  html += '<button class="filter-btn ' + (currentFilter === 'high' ? 'active' : '') + '" onclick="currentFilter=\'high\';renderOverview()">High</button>';
  html += '</div></div>';

  // Collect all findings
  const allFindings = [];

  if (data.rbacAudit?.findings) {
    data.rbacAudit.findings.forEach(f => {
      allFindings.push({type: 'RBAC', ...f, onClick: 'showRBACModal'});
    });
  }
  if (data.podSecurity?.findings) {
    data.podSecurity.findings.forEach(f => {
      allFindings.push({type: 'Pod Security', checkName: f.checkName, severity: f.severity, workload: f.workload, namespace: f.namespace, description: f.details, onClick: 'showPodSecModal'});
    });
  }
  if (data.attackPaths?.results) {
    data.attackPaths.results.filter(r => r.pathCount > 0).forEach(r => {
      const maxSev = r.critical > 0 ? 'critical' : r.high > 0 ? 'high' : 'medium';
      allFindings.push({type: 'Attack Path', severity: maxSev, workload: r.workload, namespace: r.namespace, description: r.pathCount + ' attack paths (' + r.critical + ' critical, ' + r.high + ' high)', paths: r.paths, onClick: 'showAttackPathModal'});
    });
  }
  if (data.cloudAudit?.findings) {
    data.cloudAudit.findings.forEach(f => {
      allFindings.push({type: 'Cloud IAM', severity: f.severity, checkName: f.issue, description: f.description, roleArn: f.roleArn, onClick: 'showCloudModal'});
    });
  }
  if (data.blastRadius?.results) {
    data.blastRadius.results.filter(r => r.severity === 'critical' || r.severity === 'high').forEach(r => {
      allFindings.push({type: 'Blast Radius', severity: r.severity, workload: r.workload, namespace: r.namespace, description: 'Can access ' + r.k8sPerms + ' K8s resources' + (r.cloudRoles > 0 ? ', ' + r.cloudRoles + ' cloud roles' : ''), blastData: r, onClick: 'showBlastModal'});
    });
  }

  // Filter and sort
  const filtered = currentFilter === 'all' ? allFindings : allFindings.filter(f => f.severity === currentFilter);
  const sorted = filtered.sort((a, b) => {
    const order = {critical: 0, high: 1, medium: 2, low: 3};
    return (order[a.severity] || 4) - (order[b.severity] || 4);
  });

  if (sorted.length > 0) {
    html += '<div class="top-risks">';
    sorted.slice(0, 10).forEach((f, idx) => {
      html += '<div class="risk-card" onclick="' + f.onClick + '(' + idx + ', ' + JSON.stringify(f).replace(/"/g, '&quot;') + ')">';
      html += '<div class="risk-card-header">';
      html += '<div><div class="risk-card-title">' + (f.checkName || f.workload || 'Finding') + '</div>';
      html += '<div class="risk-card-type">' + f.type + ' • ' + (f.namespace || '') + '</div></div>';
      html += '<span class="mini-badge ' + f.severity + '">' + f.severity + '</span>';
      html += '</div>';
      html += '<div class="risk-card-desc">' + (f.description || '') + '</div>';
      html += '<div class="risk-meter"><div class="risk-meter-fill ' + f.severity + '" style="width: ' + (f.severity === 'critical' ? '100' : f.severity === 'high' ? '75' : f.severity === 'medium' ? '50' : '25') + '%%"></div></div>';
      html += '</div>';
    });
    html += '</div>';
  } else {
    html += '<div class="empty-state"><div class="empty-title">No ' + (currentFilter === 'all' ? '' : currentFilter + ' ') + 'findings detected</div></div>';
  }

  document.getElementById('panel-overview').innerHTML = html;

  // Render charts
  setTimeout(() => {
    renderSeverityChart('severity-chart', {
      critical: data.summary?.criticalFindings || 0,
      high: data.summary?.highFindings || 0,
      medium: data.summary?.mediumFindings || 0,
      low: data.summary?.lowFindings || 0
    });

    // Category chart with colorful progress bars
    const catData = {
      rbac: data.rbacAudit?.findings?.length || 0,
      podsec: data.podSecurity?.findings?.length || 0,
      network: data.networkPolicy?.findings?.length || 0,
      cloud: data.cloudAudit?.findings?.length || 0
    };
    const catContainer = document.getElementById('category-chart');
    if (catContainer) {
      let catHtml = '<div style="width:100%%">';
      const maxVal = Math.max(...Object.values(catData), 1);
      const colors = {
        rbac: {color: '#a371f7', glow: 'rgba(163,113,247,0.3)', gradient: 'linear-gradient(90deg, #a371f7, #c084fc)'},
        podsec: {color: '#f0883e', glow: 'rgba(240,136,62,0.3)', gradient: 'linear-gradient(90deg, #f0883e, #fb923c)'},
        network: {color: '#39d4ff', glow: 'rgba(57,212,255,0.3)', gradient: 'linear-gradient(90deg, #39d4ff, #67e8f9)'},
        cloud: {color: '#3fb950', glow: 'rgba(63,185,80,0.3)', gradient: 'linear-gradient(90deg, #3fb950, #4ade80)'}
      };
      const labels = {rbac: 'RBAC', podsec: 'Pod Security', network: 'Network', cloud: 'Cloud'};
      Object.entries(catData).forEach(([key, val]) => {
        const pct = Math.round(val / maxVal * 100);
        const c = colors[key];
        catHtml += '<div style="margin-bottom:16px">';
        catHtml += '<div style="display:flex;justify-content:space-between;font-size:12px;margin-bottom:6px">';
        catHtml += '<span style="color:' + c.color + ';font-weight:600">' + labels[key] + '</span>';
        catHtml += '<span style="color:var(--text-secondary);font-weight:700">' + val + '</span>';
        catHtml += '</div>';
        catHtml += '<div style="height:10px;background:rgba(48,54,61,0.5);border-radius:5px;overflow:hidden;position:relative">';
        catHtml += '<div style="height:100%%;width:' + pct + '%%;background:' + c.gradient + ';border-radius:5px;box-shadow:0 0 10px ' + c.glow + ';transition:width 0.8s ease"></div>';
        catHtml += '</div></div>';
      });
      catHtml += '</div>';
      catContainer.innerHTML = catHtml;
    }

    // Risk score with circular gauge
    const riskContainer = document.getElementById('risk-chart');
    if (riskContainer) {
      const critW = 10, highW = 5, medW = 2, lowW = 1;
      const score = Math.min(100, (data.summary?.criticalFindings || 0) * critW + (data.summary?.highFindings || 0) * highW + (data.summary?.mediumFindings || 0) * medW + (data.summary?.lowFindings || 0) * lowW);
      const scoreColor = score >= 70 ? '#f85149' : score >= 40 ? '#f0883e' : score >= 20 ? '#d29922' : '#3fb950';
      const scoreLabel = score >= 70 ? 'Critical' : score >= 40 ? 'High' : score >= 20 ? 'Medium' : 'Low';
      const glowColor = score >= 70 ? 'rgba(248,81,73,0.4)' : score >= 40 ? 'rgba(240,136,62,0.4)' : score >= 20 ? 'rgba(210,153,34,0.4)' : 'rgba(63,185,80,0.4)';
      const circumference = 2 * Math.PI * 70;
      const offset = circumference - (score / 100) * circumference;

      riskContainer.innerHTML = '<div style="text-align:center;position:relative">' +
        '<svg width="180" height="180" viewBox="0 0 180 180" style="transform:rotate(-90deg)">' +
        '<circle cx="90" cy="90" r="70" fill="none" stroke="rgba(48,54,61,0.5)" stroke-width="12"/>' +
        '<circle cx="90" cy="90" r="70" fill="none" stroke="' + scoreColor + '" stroke-width="12" ' +
        'stroke-dasharray="' + circumference + '" stroke-dashoffset="' + offset + '" ' +
        'stroke-linecap="round" style="filter:drop-shadow(0 0 10px ' + glowColor + ');transition:stroke-dashoffset 1s ease"/>' +
        '</svg>' +
        '<div style="position:absolute;top:50%%;left:50%%;transform:translate(-50%%,-50%%);text-align:center">' +
        '<div style="font-size:48px;font-weight:800;color:' + scoreColor + ';text-shadow:0 0 20px ' + glowColor + '">' + score + '</div>' +
        '<div style="font-size:11px;color:var(--text-muted);text-transform:uppercase;letter-spacing:1px">Risk Score</div>' +
        '<div style="font-size:10px;color:' + scoreColor + ';font-weight:600;margin-top:2px">' + scoreLabel + '</div>' +
        '</div></div>';
    }
  }, 100);
}

function showRBACModal(idx, finding) {
  let html = '<div class="modal-grid">';
  html += '<div class="modal-stat"><div class="modal-stat-value">' + finding.severity + '</div><div class="modal-stat-label">Severity</div></div>';
  html += '<div class="modal-stat"><div class="modal-stat-value">' + (finding.affected?.length || 1) + '</div><div class="modal-stat-label">Affected Resources</div></div>';
  html += '</div>';

  html += '<div class="modal-section"><div class="modal-section-title">Description</div><p style="color:#94a3b8;line-height:1.6">' + finding.description + '</p></div>';

  if (finding.affected?.length) {
    html += '<div class="modal-section"><div class="modal-section-title">Affected Resources</div><ul class="modal-list">';
    finding.affected.forEach(a => {
      html += '<li><div class="modal-list-title">' + a.name + '<span class="modal-list-badge" style="background:rgba(99,102,241,0.2);color:#a5b4fc">' + (a.kind || 'Resource') + '</span></div>';
      html += '<div class="modal-list-meta">' + (a.namespace || 'cluster-scoped') + (a.details ? ' • ' + a.details : '') + '</div></li>';
    });
    html += '</ul></div>';
  }

  if (finding.remediation) {
    html += '<div class="modal-section"><div class="modal-section-title">Remediation</div><div class="remediation-box">' + finding.remediation + '</div></div>';
  }

  openModal('[' + finding.checkId + '] ' + finding.checkName, html);
}

function showPodSecModal(idx, finding) {
  let html = '<div class="modal-grid">';
  html += '<div class="modal-stat"><div class="modal-stat-value" style="font-size:20px">' + finding.workload + '</div><div class="modal-stat-label">Workload</div></div>';
  html += '<div class="modal-stat"><div class="modal-stat-value">' + finding.severity + '</div><div class="modal-stat-label">Severity</div></div>';
  html += '</div>';

  html += '<div class="modal-section"><div class="modal-section-title">Details</div><p style="color:#94a3b8;line-height:1.6">' + finding.description + '</p></div>';

  openModal('[' + finding.checkId + '] ' + finding.checkName, html);
}

function showAttackPathModal(idx, finding) {
  let html = '<div class="modal-grid">';
  html += '<div class="modal-stat"><div class="modal-stat-value">' + (finding.paths?.length || 0) + '</div><div class="modal-stat-label">Attack Paths</div></div>';
  html += '<div class="modal-stat"><div class="modal-stat-value">' + finding.severity + '</div><div class="modal-stat-label">Max Severity</div></div>';
  html += '</div>';

  if (finding.paths?.length) {
    html += '<div class="modal-section"><div class="modal-section-title">Attack Paths</div>';
    finding.paths.slice(0, 5).forEach((path, pIdx) => {
      html += '<div style="background:rgba(30,41,59,0.4);border-radius:12px;padding:16px;margin-bottom:16px">';
      html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">';
      html += '<span style="font-weight:600;color:#f1f5f9">Path ' + (pIdx+1) + ': ' + path.objective + '</span>';
      html += '<span class="mini-badge ' + path.severity + '">' + path.severity + ' (' + path.riskScore + ')</span>';
      html += '</div>';

      path.steps?.forEach(step => {
        html += '<div class="attack-step">';
        html += '<div class="step-number">' + step.order + '</div>';
        html += '<div class="step-content">';
        html += '<div class="step-action">' + step.action + (step.mitreId ? '<span class="step-mitre">' + step.mitreId + '</span>' : '') + '</div>';
        html += '<div class="step-target">' + step.target + '</div>';
        html += '</div></div>';
      });

      if (path.mitigations?.length) {
        html += '<div style="margin-top:12px;padding:12px;background:rgba(34,197,94,0.1);border-radius:8px">';
        html += '<div style="font-size:11px;font-weight:700;color:#4ade80;text-transform:uppercase;margin-bottom:8px">Mitigations</div>';
        path.mitigations.forEach(m => {
          html += '<div style="font-size:13px;color:#94a3b8;margin-bottom:4px">• ' + m + '</div>';
        });
        html += '</div>';
      }
      html += '</div>';
    });
    html += '</div>';
  }

  openModal('Attack Paths: ' + finding.workload, html);
}

function showCloudModal(idx, finding) {
  let html = '<div class="modal-grid">';
  html += '<div class="modal-stat"><div class="modal-stat-value">' + finding.severity + '</div><div class="modal-stat-label">Severity</div></div>';
  html += '<div class="modal-stat"><div class="modal-stat-value" style="font-size:16px;word-break:break-all">' + (finding.roleArn || 'N/A') + '</div><div class="modal-stat-label">Role ARN</div></div>';
  html += '</div>';

  html += '<div class="modal-section"><div class="modal-section-title">Issue</div><p style="color:#94a3b8;line-height:1.6">' + finding.description + '</p></div>';

  openModal(finding.checkName || finding.issue, html);
}

function showBlastModal(idx, finding) {
  const r = finding.blastData;
  let html = '<div class="modal-grid">';
  html += '<div class="modal-stat"><div class="modal-stat-value">' + r.k8sPerms + '</div><div class="modal-stat-label">K8s Resources</div></div>';
  html += '<div class="modal-stat"><div class="modal-stat-value">' + r.cloudRoles + '</div><div class="modal-stat-label">Cloud Roles</div></div>';
  html += '</div>';

  if (r.identities?.length) {
    html += '<div class="modal-section"><div class="modal-section-title">Identities</div><ul class="modal-list">';
    r.identities.forEach(id => {
      html += '<li><div class="modal-list-title">' + id.name + (id.hasCloudAccess ? '<span class="modal-list-badge" style="background:rgba(34,211,238,0.2);color:#22d3ee">Cloud Access</span>' : '') + '</div>';
      html += '<div class="modal-list-meta">' + id.namespace + (id.cloudRoleArn ? ' • ' + id.cloudRoleArn : '') + '</div></li>';
    });
    html += '</ul></div>';
  }

  if (r.k8sResources?.length) {
    html += '<div class="modal-section"><div class="modal-section-title">K8s Resources Accessible</div><ul class="modal-list">';
    r.k8sResources.slice(0, 10).forEach(res => {
      html += '<li><div class="modal-list-title">' + res.resource + '<span class="modal-list-badge ' + res.severity + '">' + res.severity + '</span></div>';
      html += '<div class="modal-list-meta">' + res.namespace + ' • ' + (res.verbs?.join(', ') || '') + ' via ' + res.viaRole + '</div></li>';
    });
    if (r.k8sResources.length > 10) html += '<li style="text-align:center;color:#64748b">... and ' + (r.k8sResources.length - 10) + ' more</li>';
    html += '</ul></div>';
  }

  if (r.cloudResources?.length) {
    html += '<div class="modal-section"><div class="modal-section-title">Cloud Resources</div><ul class="modal-list">';
    r.cloudResources.forEach(cr => {
      html += '<li><div class="modal-list-title">' + (cr.roleArn || cr.provider) + (cr.isAdmin ? '<span class="modal-list-badge" style="background:rgba(239,68,68,0.2);color:#f87171">ADMIN</span>' : '') + '</div>';
      html += '<div class="modal-list-meta">' + (cr.policyArns?.join(', ') || 'No policies') + '</div></li>';
    });
    html += '</ul></div>';
  }

  if (r.riskFactors?.length) {
    html += '<div class="modal-section"><div class="modal-section-title">Risk Factors</div>';
    r.riskFactors.forEach(rf => {
      html += '<div style="display:inline-block;background:rgba(239,68,68,0.15);color:#f87171;padding:6px 12px;border-radius:6px;font-size:12px;margin-right:8px;margin-bottom:8px">' + rf + '</div>';
    });
    html += '</div>';
  }

  openModal('Blast Radius: ' + r.workload, html);
}

function renderBlast() {
  console.log('renderBlast called');
  let html = '<div class="section-header"><div class="section-title">Blast Radius Analysis</div></div>';

  if (data.blastRadius?.results?.length) {
    // Summary stats
    let criticalCount = 0, highCount = 0, cloudCount = 0, totalK8s = 0;
    data.blastRadius.results.forEach(r => {
      if (r.severity === 'critical') criticalCount++;
      if (r.severity === 'high') highCount++;
      if (r.cloudRoles > 0) cloudCount++;
      totalK8s += r.k8sPerms || 0;
    });

    html += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px">';
    html += '<div class="stat-card"><div class="stat-value workloads">' + data.blastRadius.results.length + '</div><div class="stat-label">Workloads Analyzed</div></div>';
    html += '<div class="stat-card"><div class="stat-value critical">' + criticalCount + '</div><div class="stat-label">Critical Severity</div></div>';
    html += '<div class="stat-card"><div class="stat-value high">' + highCount + '</div><div class="stat-label">High Severity</div></div>';
    html += '<div class="stat-card"><div class="stat-value cloud">' + cloudCount + '</div><div class="stat-label">Cloud Access</div></div>';
    html += '</div>';

    // Workload cards - fan out style
    data.blastRadius.results.forEach((r, idx) => {
      const sevColor = r.severity === 'critical' ? '#ef4444' : r.severity === 'high' ? '#f97316' : r.severity === 'medium' ? '#eab308' : '#22c55e';

      html += '<div style="background:rgba(30,41,59,0.6);border:1px solid rgba(51,65,85,0.5);border-radius:16px;padding:24px;margin-bottom:20px;border-left:4px solid ' + sevColor + '">';

      // Header
      html += '<div style="display:flex;justify-content:space-between;align-items:flex-start;margin-bottom:20px">';
      html += '<div>';
      html += '<div style="font-size:20px;font-weight:700;color:#f1f5f9">' + r.workload + '</div>';
      html += '<div style="font-size:13px;color:#64748b;margin-top:4px">' + r.namespace + ' / ' + r.kind + '</div>';
      if (r.serviceAccount) {
        html += '<div style="font-size:12px;color:#a78bfa;margin-top:4px">Service Account: ' + r.serviceAccount + '</div>';
      }
      html += '</div>';
      html += '<span class="mini-badge ' + r.severity + '" style="font-size:12px;padding:6px 14px">' + r.severity.toUpperCase() + '</span>';
      html += '</div>';

      // Fan-out visualization using SVG with zoom controls
      html += '<div style="position:relative;margin-bottom:16px">';
      html += '<div style="position:absolute;top:8px;right:8px;z-index:10;display:flex;gap:4px">';
      html += '<button onclick="zoomViz(\'blast-viz-' + idx + '\', 0.2)" style="width:28px;height:28px;border-radius:6px;background:rgba(51,65,85,0.8);border:1px solid rgba(71,85,105,0.5);color:#94a3b8;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center">+</button>';
      html += '<button onclick="zoomViz(\'blast-viz-' + idx + '\', -0.2)" style="width:28px;height:28px;border-radius:6px;background:rgba(51,65,85,0.8);border:1px solid rgba(71,85,105,0.5);color:#94a3b8;cursor:pointer;font-size:16px;display:flex;align-items:center;justify-content:center">-</button>';
      html += '<button onclick="resetZoom(\'blast-viz-' + idx + '\')" style="height:28px;padding:0 10px;border-radius:6px;background:rgba(51,65,85,0.8);border:1px solid rgba(71,85,105,0.5);color:#94a3b8;cursor:pointer;font-size:11px">Reset</button>';
      html += '</div>';
      html += '<div id="blast-viz-' + idx + '" style="height:350px;background:rgba(15,23,42,0.4);border-radius:12px;position:relative;overflow:hidden"></div>';
      html += '</div>';

      // Access summary grid
      html += '<div style="display:grid;grid-template-columns:repeat(3,1fr);gap:12px;margin-bottom:16px">';

      // K8s Resources
      html += '<div style="background:rgba(96,165,250,0.1);border:1px solid rgba(96,165,250,0.3);border-radius:10px;padding:14px">';
      html += '<div style="font-size:11px;color:#60a5fa;text-transform:uppercase;font-weight:600;margin-bottom:8px">K8s Resources</div>';
      html += '<div style="font-size:28px;font-weight:700;color:#60a5fa">' + (r.k8sPerms || 0) + '</div>';
      if (r.k8sResources?.length > 0) {
        html += '<div style="margin-top:8px;font-size:11px;color:#94a3b8">';
        const resourceTypes = {};
        r.k8sResources.forEach(res => { resourceTypes[res.kind] = (resourceTypes[res.kind] || 0) + 1; });
        Object.entries(resourceTypes).slice(0, 3).forEach(([k, v]) => {
          html += '<div>' + v + ' ' + k + '</div>';
        });
        html += '</div>';
      }
      html += '</div>';

      // Cloud Roles
      html += '<div style="background:rgba(34,211,238,0.1);border:1px solid rgba(34,211,238,0.3);border-radius:10px;padding:14px">';
      html += '<div style="font-size:11px;color:#22d3ee;text-transform:uppercase;font-weight:600;margin-bottom:8px">Cloud Roles</div>';
      html += '<div style="font-size:28px;font-weight:700;color:#22d3ee">' + (r.cloudRoles || 0) + '</div>';
      if (r.cloudResources?.length > 0) {
        html += '<div style="margin-top:8px;font-size:11px;color:#94a3b8">';
        r.cloudResources.slice(0, 2).forEach(cr => {
          html += '<div style="overflow:hidden;text-overflow:ellipsis;white-space:nowrap">' + cr.provider.toUpperCase();
          if (cr.isAdmin) html += ' <span style="color:#ef4444">(Admin)</span>';
          html += '</div>';
        });
        html += '</div>';
      }
      html += '</div>';

      // Identities
      html += '<div style="background:rgba(167,139,250,0.1);border:1px solid rgba(167,139,250,0.3);border-radius:10px;padding:14px">';
      html += '<div style="font-size:11px;color:#a78bfa;text-transform:uppercase;font-weight:600;margin-bottom:8px">Identities</div>';
      html += '<div style="font-size:28px;font-weight:700;color:#a78bfa">' + (r.identities?.length || 1) + '</div>';
      if (r.identities?.length > 0) {
        html += '<div style="margin-top:8px;font-size:11px;color:#94a3b8">';
        r.identities.slice(0, 2).forEach(id => {
          html += '<div>' + id.name;
          if (id.hasCloudAccess) html += ' <span style="color:#22d3ee">→ Cloud</span>';
          html += '</div>';
        });
        html += '</div>';
      }
      html += '</div>';
      html += '</div>';

      // Risk factors
      if (r.riskFactors?.length > 0) {
        html += '<div style="display:flex;flex-wrap:wrap;gap:8px">';
        r.riskFactors.forEach(rf => {
          html += '<span style="background:rgba(239,68,68,0.15);color:#f87171;padding:6px 12px;border-radius:6px;font-size:11px;font-weight:500">' + rf + '</span>';
        });
        html += '</div>';
      }

      // Click to expand
      html += '<div style="margin-top:16px;padding-top:16px;border-top:1px solid rgba(51,65,85,0.5);display:flex;justify-content:space-between;align-items:center">';
      html += '<span style="font-size:12px;color:#64748b">Click to view full blast radius details</span>';
      html += '<button style="background:rgba(99,102,241,0.2);border:1px solid rgba(99,102,241,0.3);border-radius:8px;padding:8px 16px;color:#a5b4fc;cursor:pointer;font-size:12px;font-weight:600" onclick="showBlastModal(' + idx + ', {blastData: ' + JSON.stringify(r).replace(/"/g, '&quot;') + '})">View Details</button>';
      html += '</div>';

      html += '</div>';
    });
  } else {
    html += '<div class="empty-state"><div class="empty-title">No blast radius data available</div></div>';
  }

  document.getElementById('panel-blast').innerHTML = html;

  // Render SVG visualizations for each workload
  if (data.blastRadius?.results?.length) {
    data.blastRadius.results.forEach((r, idx) => {
      setTimeout(() => renderBlastSVG('blast-viz-' + idx, r), 50);
    });
  }
}

// Zoom state tracking
const zoomLevels = {};

function zoomViz(containerId, delta) {
  if (!zoomLevels[containerId]) zoomLevels[containerId] = 1;
  zoomLevels[containerId] = Math.max(0.5, Math.min(3, zoomLevels[containerId] + delta));
  const el = document.getElementById(containerId);
  if (el) {
    const svg = el.querySelector('svg');
    if (svg) {
      svg.style.transform = 'scale(' + zoomLevels[containerId] + ')';
      svg.style.transformOrigin = 'center center';
    } else {
      el.style.transform = 'scale(' + zoomLevels[containerId] + ')';
      el.style.transformOrigin = 'left center';
    }
  }
}

function resetZoom(containerId) {
  zoomLevels[containerId] = 1;
  const el = document.getElementById(containerId);
  if (el) {
    const svg = el.querySelector('svg');
    if (svg) {
      svg.style.transform = 'scale(1)';
    } else {
      el.style.transform = 'scale(1)';
    }
  }
}

function renderBlastSVG(containerId, result) {
  const container = document.getElementById(containerId);
  if (!container) return;

  const width = container.clientWidth || 700;
  const height = 350;
  const centerX = width / 2;
  const centerY = height / 2;

  let svg = '<svg width="' + width + '" height="' + height + '" style="display:block;transition:transform 0.2s ease">';

  // Draw connections first (behind nodes)
  const targets = [];

  // Add service account
  if (result.serviceAccount) {
    targets.push({ type: 'sa', name: result.serviceAccount, color: '#a78bfa' });
  }

  // Add K8s resources (sample)
  if (result.k8sResources?.length > 0) {
    result.k8sResources.slice(0, 5).forEach(res => {
      targets.push({ type: 'k8s', name: res.resource?.substring(0, 15) || 'resource', kind: res.kind, color: '#60a5fa', severity: res.severity });
    });
  }

  // Add cloud roles
  if (result.cloudResources?.length > 0) {
    result.cloudResources.forEach(cr => {
      targets.push({ type: 'cloud', name: cr.provider.toUpperCase(), isAdmin: cr.isAdmin, color: '#22d3ee' });
    });
  }

  // Calculate positions in a fan pattern
  const angleStep = targets.length > 0 ? Math.PI / (targets.length + 1) : 0;
  const radius = 130;

  targets.forEach((t, i) => {
    const angle = -Math.PI / 2 - Math.PI / 2 + angleStep * (i + 1);
    const x = centerX + radius * Math.cos(angle);
    const y = centerY + radius * Math.sin(angle);
    t.x = x;
    t.y = y;

    // Draw line
    svg += '<line x1="' + centerX + '" y1="' + centerY + '" x2="' + x + '" y2="' + y + '" stroke="' + t.color + '" stroke-width="2" stroke-opacity="0.5" stroke-dasharray="6,4"/>';
  });

  // Draw center node (workload)
  svg += '<circle cx="' + centerX + '" cy="' + centerY + '" r="50" fill="rgba(96,165,250,0.2)" stroke="#60a5fa" stroke-width="3"/>';
  svg += '<text x="' + centerX + '" y="' + (centerY - 8) + '" text-anchor="middle" fill="#60a5fa" font-size="12" font-weight="700">WORKLOAD</text>';
  svg += '<text x="' + centerX + '" y="' + (centerY + 8) + '" text-anchor="middle" fill="#94a3b8" font-size="11">' + (result.workload?.substring(0, 15) || '') + '</text>';

  // Draw target nodes
  targets.forEach(t => {
    const nodeRadius = 38;
    let fillColor = 'rgba(167,139,250,0.2)';
    let label = 'SA';

    if (t.type === 'k8s') {
      fillColor = 'rgba(96,165,250,0.2)';
      label = t.kind?.substring(0, 8) || 'K8S';
    } else if (t.type === 'cloud') {
      fillColor = t.isAdmin ? 'rgba(239,68,68,0.2)' : 'rgba(34,211,238,0.2)';
      label = t.name;
    }

    svg += '<circle cx="' + t.x + '" cy="' + t.y + '" r="' + nodeRadius + '" fill="' + fillColor + '" stroke="' + t.color + '" stroke-width="2"/>';
    svg += '<text x="' + t.x + '" y="' + (t.y - 5) + '" text-anchor="middle" fill="' + t.color + '" font-size="11" font-weight="600">' + label + '</text>';
    svg += '<text x="' + t.x + '" y="' + (t.y + 10) + '" text-anchor="middle" fill="#64748b" font-size="9">' + (t.name?.substring(0, 12) || '') + '</text>';
    if (t.isAdmin) {
      svg += '<text x="' + t.x + '" y="' + (t.y + 22) + '" text-anchor="middle" fill="#ef4444" font-size="9" font-weight="700">ADMIN</text>';
    }
  });

  // If no targets, show message
  if (targets.length === 0) {
    svg += '<text x="' + centerX + '" y="' + (centerY + 70) + '" text-anchor="middle" fill="#64748b" font-size="14">No direct resource access detected</text>';
  }

  svg += '</svg>';
  container.innerHTML = svg;
}


function renderAttack() {
  console.log('renderAttack called');
  let html = '<div class="section-header"><div class="section-title">Attack Path Analysis</div></div>';

  if (data.attackPaths?.results?.length) {
    // Summary cards
    const summary = data.attackPaths.summary || {};
    html += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px">';
    html += '<div class="stat-card"><div class="stat-value paths">' + (summary.totalPaths || 0) + '</div><div class="stat-label">Total Paths</div></div>';
    html += '<div class="stat-card"><div class="stat-value critical">' + (summary.criticalPaths || 0) + '</div><div class="stat-label">Critical</div></div>';
    html += '<div class="stat-card"><div class="stat-value high">' + (summary.highPaths || 0) + '</div><div class="stat-label">High</div></div>';
    html += '<div class="stat-card"><div class="stat-value cloud">' + (summary.cloudPaths || 0) + '</div><div class="stat-label">Cloud Impact</div></div>';
    html += '</div>';

    // Attack path visualization for each workload
    data.attackPaths.results.forEach((r, idx) => {
      if (!r.paths || r.paths.length === 0) return;

      html += '<div style="background:rgba(30,41,59,0.6);border:1px solid rgba(51,65,85,0.5);border-radius:16px;padding:20px;margin-bottom:16px">';
      html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">';
      html += '<div><span style="font-size:16px;font-weight:700;color:#f1f5f9">' + r.workload + '</span>';
      html += '<span style="font-size:12px;color:#64748b;margin-left:12px">' + r.namespace + '</span></div>';
      html += '<div>';
      if (r.critical > 0) html += '<span class="mini-badge critical" style="margin-left:8px">' + r.critical + ' critical</span>';
      if (r.high > 0) html += '<span class="mini-badge high" style="margin-left:8px">' + r.high + ' high</span>';
      if (r.affectsCloud) html += '<span class="mini-badge cloud" style="margin-left:8px">Cloud Impact</span>';
      html += '</div></div>';

      // Visual attack path flow
      r.paths.slice(0, 3).forEach((path, pIdx) => {
        const sevColor = path.severity === 'critical' ? '#ef4444' : path.severity === 'high' ? '#f97316' : '#eab308';
        html += '<div style="background:rgba(15,23,42,0.6);border-radius:12px;padding:16px;margin-bottom:12px;border-left:4px solid ' + sevColor + '">';
        html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:12px">';
        html += '<span style="font-size:13px;font-weight:600;color:#94a3b8">Path ' + (pIdx + 1) + ': ' + path.objective + '</span>';
        html += '<span class="mini-badge ' + path.severity + '">Risk: ' + path.riskScore + '</span>';
        html += '</div>';

        // Horizontal step flow with zoom controls
        const pathVizId = 'attack-path-' + idx + '-' + pIdx;
        html += '<div style="position:relative">';
        html += '<div style="position:absolute;top:4px;right:4px;z-index:10;display:flex;gap:4px">';
        html += '<button onclick="zoomViz(\'' + pathVizId + '\', 0.2)" style="width:24px;height:24px;border-radius:4px;background:rgba(51,65,85,0.8);border:1px solid rgba(71,85,105,0.5);color:#94a3b8;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center">+</button>';
        html += '<button onclick="zoomViz(\'' + pathVizId + '\', -0.2)" style="width:24px;height:24px;border-radius:4px;background:rgba(51,65,85,0.8);border:1px solid rgba(71,85,105,0.5);color:#94a3b8;cursor:pointer;font-size:14px;display:flex;align-items:center;justify-content:center">-</button>';
        html += '<button onclick="resetZoom(\'' + pathVizId + '\')" style="height:24px;padding:0 8px;border-radius:4px;background:rgba(51,65,85,0.8);border:1px solid rgba(71,85,105,0.5);color:#94a3b8;cursor:pointer;font-size:10px">Reset</button>';
        html += '</div>';
        html += '<div id="' + pathVizId + '" style="display:flex;align-items:center;gap:8px;overflow:auto;padding:8px 0;transition:transform 0.2s ease">';
        if (path.steps) {
          path.steps.forEach((step, sIdx) => {
            const nodeColor = sIdx === 0 ? '#60a5fa' : sIdx === path.steps.length - 1 ? '#ef4444' : '#a78bfa';
            html += '<div style="flex-shrink:0;text-align:center">';
            html += '<div style="width:110px;height:100px;border-radius:12px;background:rgba(99,102,241,0.1);border:2px solid ' + nodeColor + ';display:flex;flex-direction:column;align-items:center;justify-content:center;padding:10px">';
            html += '<div style="font-size:12px;font-weight:700;color:' + nodeColor + ';margin-bottom:6px">' + step.action + '</div>';
            html += '<div style="font-size:10px;color:#64748b;overflow:hidden;text-overflow:ellipsis;max-width:95px" title="' + step.target + '">' + (step.target || '').substring(0, 18) + '</div>';
            if (step.mitreId) html += '<div style="font-size:9px;color:#6366f1;background:rgba(99,102,241,0.2);padding:2px 6px;border-radius:4px;margin-top:4px">' + step.mitreId + '</div>';
            html += '</div></div>';
            if (sIdx < path.steps.length - 1) {
              html += '<div style="color:#475569;font-size:24px">→</div>';
            }
          });
        }
        html += '</div>';
        html += '</div>';

        // Mitigations
        if (path.mitigations && path.mitigations.length > 0) {
          html += '<div style="margin-top:12px;padding:10px;background:rgba(34,197,94,0.1);border-radius:8px">';
          html += '<div style="font-size:10px;font-weight:700;color:#4ade80;text-transform:uppercase;margin-bottom:6px">Mitigations</div>';
          path.mitigations.slice(0, 2).forEach(m => {
            html += '<div style="font-size:11px;color:#94a3b8;margin-bottom:2px">• ' + m + '</div>';
          });
          html += '</div>';
        }
        html += '</div>';
      });

      if (r.paths.length > 3) {
        html += '<div style="text-align:center;color:#64748b;font-size:12px;padding:8px">+ ' + (r.paths.length - 3) + ' more paths</div>';
      }
      html += '</div>';
    });
  } else {
    html += '<div class="empty-state"><div class="empty-title">No attack paths found</div></div>';
  }

  document.getElementById('panel-attack').innerHTML = html;
}

function renderRBAC() {
  let html = '<div class="section-header"><div class="section-title">RBAC Security Audit</div></div>';

  if (data.rbacAudit?.findings?.length) {
    html += '<div class="findings-grid">';
    data.rbacAudit.findings.forEach((f, idx) => {
      html += '<div class="finding-card ' + f.severity + '" onclick="showRBACModal(' + idx + ', ' + JSON.stringify(f).replace(/"/g, '&quot;') + ')">';
      html += '<div class="finding-header">';
      html += '<span class="finding-severity ' + f.severity + '">' + f.severity + '</span>';
      html += '<div class="finding-content">';
      html += '<div class="finding-title">[' + f.checkId + '] ' + f.checkName + '</div>';
      html += '<div class="finding-meta">' + f.namespace + ' • ' + f.subject + '</div>';
      html += '<div class="finding-desc">' + f.description + '</div>';
      html += '</div></div></div>';
    });
    html += '</div>';
  } else {
    html += '<div class="empty-state"><div class="empty-title">No RBAC findings detected</div></div>';
  }

  document.getElementById('panel-rbac').innerHTML = html;
}

function renderPodSec() {
  let html = '<div class="section-header"><div class="section-title">Pod Security Audit</div></div>';

  if (data.podSecurity?.findings?.length) {
    html += '<div class="findings-grid">';
    data.podSecurity.findings.forEach((f, idx) => {
      html += '<div class="finding-card ' + f.severity + '" onclick="showPodSecModal(' + idx + ', ' + JSON.stringify(f).replace(/"/g, '&quot;') + ')">';
      html += '<div class="finding-header">';
      html += '<span class="finding-severity ' + f.severity + '">' + f.severity + '</span>';
      html += '<div class="finding-content">';
      html += '<div class="finding-title">[' + f.checkId + '] ' + f.checkName + '</div>';
      html += '<div class="finding-meta">' + f.namespace + '/' + f.workload + (f.container ? ' • ' + f.container : '') + '</div>';
      html += '<div class="finding-desc">' + f.details + '</div>';
      html += '</div></div></div>';
    });
    html += '</div>';
  } else {
    html += '<div class="empty-state"><div class="empty-title">No pod security findings detected</div></div>';
  }

  document.getElementById('panel-podsec').innerHTML = html;
}

function renderNetPol() {
  let html = '<div class="section-header"><div class="section-title">Network Policy Audit</div></div>';

  // Summary stats
  const summary = data.networkPolicy?.summary || {};
  html += '<div style="display:grid;grid-template-columns:repeat(4,1fr);gap:16px;margin-bottom:24px">';
  html += '<div class="stat-card"><div class="stat-value high">' + (summary.totalFindings || 0) + '</div><div class="stat-label">Total Findings</div></div>';
  html += '<div class="stat-card"><div class="stat-value critical">' + (summary.workloadsNoPolicy || 0) + '</div><div class="stat-label">No Policy</div></div>';
  html += '<div class="stat-card"><div class="stat-value critical">' + (summary.externalExposed || 0) + '</div><div class="stat-label">External Exposed</div></div>';
  html += '<div class="stat-card"><div class="stat-value workloads">' + (data.networkPolicy?.suggestions?.length || 0) + '</div><div class="stat-label">Suggested Policies</div></div>';
  html += '</div>';

  if (data.networkPolicy?.findings?.length) {
    html += '<div style="font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:16px">Findings</div>';
    html += '<div class="findings-grid">';
    data.networkPolicy.findings.forEach(f => {
      html += '<div class="finding-card ' + f.severity + '">';
      html += '<div class="finding-header">';
      html += '<span class="finding-severity ' + f.severity + '">' + f.severity + '</span>';
      html += '<div class="finding-content">';
      html += '<div class="finding-title">[' + f.checkId + '] ' + f.checkName + '</div>';
      html += '<div class="finding-meta">' + f.namespace + '/' + f.workload + '</div>';
      html += '<div class="finding-desc">' + f.details + '</div>';
      html += '</div></div></div>';
    });
    html += '</div>';
  }

  // Suggested policies section
  if (data.networkPolicy?.suggestions?.length) {
    html += '<div style="font-size:18px;font-weight:700;color:#f1f5f9;margin:24px 0 16px 0">Suggested Network Policies</div>';
    html += '<div style="color:#94a3b8;margin-bottom:16px">Ready-to-apply NetworkPolicy YAML for workloads without network policies</div>';
    html += '<div class="findings-grid">';
    data.networkPolicy.suggestions.forEach((s, idx) => {
      html += '<div class="finding-card medium" style="cursor:pointer" onclick="togglePolicyYAML(' + idx + ')">';
      html += '<div class="finding-header">';
      html += '<span class="finding-severity workloads">suggested</span>';
      html += '<div class="finding-content">';
      html += '<div class="finding-title">' + s.policyName + '</div>';
      html += '<div class="finding-meta">' + s.namespace + '/' + s.workload + ' (' + s.workloadKind + ')' + (s.services?.length ? ' • Services: ' + s.services.join(', ') : '') + '</div>';
      html += '<div class="finding-desc">' + s.description + '</div>';
      html += '</div></div>';
      html += '<div id="policy-yaml-' + idx + '" style="display:none;margin-top:12px">';
      html += '<pre style="background:rgba(15,23,42,0.8);border:1px solid rgba(51,65,85,0.5);border-radius:8px;padding:12px;overflow-x:auto;font-size:12px;color:#e2e8f0;white-space:pre-wrap">' + escapeHtml(s.yaml) + '</pre>';
      html += '<button onclick="event.stopPropagation();copyToClipboard(\'' + btoa(s.yaml) + '\')" style="margin-top:8px;padding:8px 16px;background:rgba(59,130,246,0.2);border:1px solid rgba(59,130,246,0.3);border-radius:6px;color:#60a5fa;cursor:pointer;font-size:12px">Copy YAML</button>';
      html += '</div></div>';
    });
    html += '</div>';
  }

  if (!data.networkPolicy?.findings?.length && !data.networkPolicy?.suggestions?.length) {
    html += '<div class="empty-state"><div class="empty-title">No network policy findings or suggestions</div></div>';
  }

  document.getElementById('panel-netpol').innerHTML = html;
}

function togglePolicyYAML(idx) {
  const el = document.getElementById('policy-yaml-' + idx);
  el.style.display = el.style.display === 'none' ? 'block' : 'none';
}

function copyToClipboard(b64) {
  const yaml = atob(b64);
  navigator.clipboard.writeText(yaml).then(() => {
    alert('YAML copied to clipboard!');
  });
}

function escapeHtml(text) {
  const div = document.createElement('div');
  div.textContent = text;
  return div.innerHTML;
}

function renderCloud() {
  let html = '<div class="section-header"><div class="section-title">Cloud IAM Audit</div></div>';

  if (data.cloudAudit?.findings?.length) {
    html += '<div class="findings-grid">';
    data.cloudAudit.findings.forEach((f, idx) => {
      html += '<div class="finding-card ' + f.severity + '" onclick="showCloudModal(' + idx + ', ' + JSON.stringify(f).replace(/"/g, '&quot;') + ')">';
      html += '<div class="finding-header">';
      html += '<span class="finding-severity ' + f.severity + '">' + f.severity + '</span>';
      html += '<div class="finding-content">';
      html += '<div class="finding-title">' + f.issue + '</div>';
      html += '<div class="finding-meta">' + f.provider + ' • ' + f.roleArn + '</div>';
      html += '<div class="finding-desc">' + f.description + '</div>';
      html += '</div></div></div>';
    });
    html += '</div>';
  } else {
    html += '<div class="empty-state"><div class="empty-title">No cloud IAM findings (use --include-cloud flag)</div></div>';
  }

  document.getElementById('panel-cloud').innerHTML = html;
}

function renderPermissions() {
  let html = '<div class="section-header"><div class="section-title">Permissions Audit - Who Can Access What</div></div>';

  const perms = data.permissions;
  if (!perms) {
    html += '<div class="empty-state"><div class="empty-title">No permissions data available</div></div>';
    document.getElementById('panel-permissions').innerHTML = html;
    return;
  }

  // Summary cards
  html += '<div style="display:grid;grid-template-columns:repeat(6,1fr);gap:16px;margin-bottom:24px">';
  html += '<div class="stat-card"><div class="stat-value critical">' + (perms.summary?.totalDangerous || 0) + '</div><div class="stat-label">Dangerous Permissions</div></div>';
  html += '<div class="stat-card"><div class="stat-value critical">' + (perms.summary?.criticalCount || 0) + '</div><div class="stat-label">Critical</div></div>';
  html += '<div class="stat-card"><div class="stat-value high">' + (perms.summary?.highCount || 0) + '</div><div class="stat-label">High</div></div>';
  html += '<div class="stat-card"><div class="stat-value workloads">' + (perms.summary?.secretAccessors || 0) + '</div><div class="stat-label">Secret Accessors</div></div>';
  html += '<div class="stat-card"><div class="stat-value paths">' + (perms.summary?.podExecUsers || 0) + '</div><div class="stat-label">Pod Exec Users</div></div>';
  html += '<div class="stat-card"><div class="stat-value critical">' + (perms.summary?.clusterAdmins || 0) + '</div><div class="stat-label">Cluster Admins</div></div>';
  html += '</div>';

  // Dangerous permissions table
  if (perms.dangerousPerms?.length > 0) {
    html += '<div style="background:rgba(30,41,59,0.6);border:1px solid rgba(51,65,85,0.5);border-radius:16px;padding:20px;margin-bottom:24px">';
    html += '<div style="font-size:18px;font-weight:700;color:#f1f5f9;margin-bottom:16px">Dangerous Permissions Summary</div>';
    html += '<table style="width:100%%;border-collapse:collapse">';
    html += '<thead><tr style="border-bottom:1px solid rgba(51,65,85,0.5)">';
    html += '<th style="text-align:left;padding:12px;color:#94a3b8;font-weight:600">Subject</th>';
    html += '<th style="text-align:left;padding:12px;color:#94a3b8;font-weight:600">Kind</th>';
    html += '<th style="text-align:left;padding:12px;color:#94a3b8;font-weight:600">Namespace</th>';
    html += '<th style="text-align:left;padding:12px;color:#94a3b8;font-weight:600">Permission</th>';
    html += '<th style="text-align:left;padding:12px;color:#94a3b8;font-weight:600">Severity</th>';
    html += '</tr></thead><tbody>';
    perms.dangerousPerms.forEach(p => {
      const sevColor = p.severity === 'critical' ? '#f87171' : p.severity === 'high' ? '#fb923c' : '#fbbf24';
      html += '<tr style="border-bottom:1px solid rgba(51,65,85,0.3)">';
      html += '<td style="padding:12px;color:#e2e8f0;font-weight:500">' + p.subject + '</td>';
      html += '<td style="padding:12px;color:#94a3b8">' + p.subjectKind + '</td>';
      html += '<td style="padding:12px;color:#94a3b8">' + p.namespace + '</td>';
      html += '<td style="padding:12px;color:#e2e8f0">' + p.permission + '</td>';
      html += '<td style="padding:12px"><span class="mini-badge ' + p.severity + '">' + p.severity + '</span></td>';
      html += '</tr>';
    });
    html += '</tbody></table></div>';
  }

  // Permission category sections
  const categories = [
    { title: 'Secret Access', data: perms.secretAccess, icon: 'Secrets', desc: 'Who can read secrets' },
    { title: 'Pod Exec', data: perms.podExec, icon: 'Exec', desc: 'Who can execute commands in pods' },
    { title: 'Pod Create', data: perms.podCreate, icon: 'Create', desc: 'Who can create pods' },
    { title: 'Cluster Admin', data: perms.clusterAdmin, icon: 'Admin', desc: 'Who can create cluster role bindings' },
    { title: 'Impersonate', data: perms.impersonate, icon: 'Impersonate', desc: 'Who can impersonate other identities' }
  ];

  html += '<div style="display:grid;grid-template-columns:repeat(2,1fr);gap:16px">';
  categories.forEach(cat => {
    html += '<div style="background:rgba(30,41,59,0.6);border:1px solid rgba(51,65,85,0.5);border-radius:16px;padding:20px">';
    html += '<div style="display:flex;justify-content:space-between;align-items:center;margin-bottom:16px">';
    html += '<div><div style="font-size:16px;font-weight:700;color:#f1f5f9">' + cat.title + '</div>';
    html += '<div style="font-size:12px;color:#64748b">' + cat.desc + '</div></div>';
    let totalSubjects = 0;
    if (cat.data) cat.data.forEach(r => totalSubjects += r.subjects?.length || 0);
    html += '<div style="font-size:24px;font-weight:700;color:#60a5fa">' + totalSubjects + '</div>';
    html += '</div>';

    if (cat.data?.length > 0) {
      html += '<div style="max-height:200px;overflow-y:auto">';
      cat.data.forEach(result => {
        const ns = result.namespace || 'cluster-wide';
        html += '<div style="margin-bottom:12px;padding:12px;background:rgba(15,23,42,0.4);border-radius:8px">';
        html += '<div style="font-size:12px;color:#64748b;margin-bottom:8px">' + ns + ' - ' + result.verb + ' ' + result.resource + '</div>';
        if (result.subjects) {
          result.subjects.slice(0, 5).forEach(s => {
            html += '<div style="display:flex;align-items:center;gap:8px;margin-bottom:4px">';
            html += '<span style="font-size:11px;padding:2px 6px;background:rgba(99,102,241,0.2);color:#a5b4fc;border-radius:4px">' + s.kind + '</span>';
            html += '<span style="color:#e2e8f0;font-size:13px">' + s.name + '</span>';
            if (s.viaRole) html += '<span style="color:#64748b;font-size:11px">via ' + s.viaRole + '</span>';
            html += '</div>';
          });
          if (result.subjects.length > 5) {
            html += '<div style="color:#64748b;font-size:11px;margin-top:4px">+ ' + (result.subjects.length - 5) + ' more</div>';
          }
        }
        html += '</div>';
      });
      html += '</div>';
    } else {
      html += '<div style="color:#64748b;font-size:13px;text-align:center;padding:20px">No subjects found</div>';
    }
    html += '</div>';
  });
  html += '</div>';

  document.getElementById('panel-permissions').innerHTML = html;
}

// Keyboard shortcuts
document.addEventListener('keydown', (e) => {
  if (e.key === 'Escape') closeModal();
});

// Initial render
try {
  console.log('Rendering overview...');
  renderOverview();
  console.log('Rendering blast...');
  renderBlast();
  console.log('Rendering attack...');
  renderAttack();
  console.log('Rendering permissions...');
  renderPermissions();
  console.log('Rendering rbac...');
  renderRBAC();
  console.log('Rendering podsec...');
  renderPodSec();
  console.log('Rendering netpol...');
  renderNetPol();
  console.log('Rendering cloud...');
  renderCloud();
  console.log('All renders complete!');
} catch(e) {
  console.error('Render error:', e);
}
  </script>
</body>
</html>`
