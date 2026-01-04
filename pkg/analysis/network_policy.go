package analysis

import (
	"fmt"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type NetworkPolicyResult struct {
	Findings      []NetworkPolicyFinding
	Summary       NetworkPolicySummary
	ChecksRun     []string
	TotalFindings int
}

type NetworkPolicySummary struct {
	Critical                    int
	High                        int
	Medium                      int
	Low                         int
	WorkloadsWithoutPolicy      int
	WorkloadsExternallyExposed  int
	TotalNetworkPolicies        int
	ByCategory                  map[string]int
}

type NetworkPolicyFinding struct {
	CheckID     string
	Category    string
	Severity    graph.Severity
	Title       string
	Description string
	Affected    []AffectedNetworkResource
	Remediation string
}

type AffectedNetworkResource struct {
	Kind      string
	Namespace string
	Name      string
	Details   string
	Services  []string
}

type NetworkPolicyCheck struct {
	ID          string
	Name        string
	Category    string
	Severity    graph.Severity
	Description string
	Remediation string
}

var NetworkPolicyChecks = []NetworkPolicyCheck{
	{
		ID:          "NET001",
		Name:        "No Network Policy",
		Category:    "missing_policy",
		Severity:    graph.SeverityHigh,
		Description: "Workloads without network policies have unrestricted network access",
		Remediation: "Create NetworkPolicy to restrict ingress and egress traffic",
	},
	{
		ID:          "NET002",
		Name:        "Externally Exposed Without Policy",
		Category:    "external_exposure",
		Severity:    graph.SeverityCritical,
		Description: "Workloads exposed via LoadBalancer/NodePort without network policy",
		Remediation: "Add NetworkPolicy to restrict access to externally exposed services",
	},
	{
		ID:          "NET003",
		Name:        "Allow All Ingress",
		Category:    "overly_permissive",
		Severity:    graph.SeverityMedium,
		Description: "Network policy allows ingress from all sources",
		Remediation: "Restrict ingress to specific pod selectors or namespaces",
	},
	{
		ID:          "NET004",
		Name:        "Allow All Egress",
		Category:    "overly_permissive",
		Severity:    graph.SeverityMedium,
		Description: "Network policy allows egress to all destinations",
		Remediation: "Restrict egress to specific pod selectors, namespaces, or IP blocks",
	},
	{
		ID:          "NET005",
		Name:        "Wide CIDR Block",
		Category:    "overly_permissive",
		Severity:    graph.SeverityMedium,
		Description: "Network policy allows traffic from/to wide IP ranges (0.0.0.0/0 or large blocks)",
		Remediation: "Restrict IP blocks to specific, necessary ranges",
	},
	{
		ID:          "NET006",
		Name:        "No Ingress Policy",
		Category:    "incomplete_policy",
		Severity:    graph.SeverityMedium,
		Description: "Workload has egress policy but no ingress policy",
		Remediation: "Add ingress rules to fully protect the workload",
	},
	{
		ID:          "NET007",
		Name:        "No Egress Policy",
		Category:    "incomplete_policy",
		Severity:    graph.SeverityLow,
		Description: "Workload has ingress policy but no egress policy",
		Remediation: "Add egress rules to control outbound traffic",
	},
	{
		ID:          "NET008",
		Name:        "Host Network Exposed",
		Category:    "host_exposure",
		Severity:    graph.SeverityHigh,
		Description: "Workload using host network bypasses network policies entirely",
		Remediation: "Remove hostNetwork: true or ensure node-level firewalls are in place",
	},
}

type NetworkPolicyOptions struct {
	ChecksToRun   []string
	SkipChecks    []string
	IncludeSystem bool
	Namespace     string
}

func RunNetworkPolicyAudit(g *graph.Graph, opts NetworkPolicyOptions) *NetworkPolicyResult {
	result := &NetworkPolicyResult{
		ChecksRun: make([]string, 0),
		Summary: NetworkPolicySummary{
			ByCategory: make(map[string]int),
		},
	}

	checksToRun := make(map[string]bool)
	if len(opts.ChecksToRun) > 0 {
		for _, c := range opts.ChecksToRun {
			checksToRun[c] = true
		}
	} else {
		for _, c := range NetworkPolicyChecks {
			checksToRun[c.ID] = true
		}
	}

	for _, skip := range opts.SkipChecks {
		delete(checksToRun, skip)
	}

	result.Summary.TotalNetworkPolicies = len(g.GetNodesByType(graph.NodeNetworkPolicy))

	// Build workload exposure map
	workloads := g.GetNodesByType(graph.NodeWorkload)
	workloadExposures := make(map[string]*workloadNetworkInfo)

	for _, workload := range workloads {
		if !opts.IncludeSystem && isSystemNamespace(workload.Namespace) {
			continue
		}
		if opts.Namespace != "" && workload.Namespace != opts.Namespace {
			continue
		}

		info := analyzeWorkloadNetwork(g, workload)
		workloadExposures[workload.ID] = info

		if !info.HasAnyPolicy {
			result.Summary.WorkloadsWithoutPolicy++
		}
		if info.IsExternallyExposed {
			result.Summary.WorkloadsExternallyExposed++
		}
	}

	for _, check := range NetworkPolicyChecks {
		if !checksToRun[check.ID] {
			continue
		}

		result.ChecksRun = append(result.ChecksRun, check.ID)

		var affected []AffectedNetworkResource

		switch check.ID {
		case "NET001":
			affected = checkNoNetworkPolicy(workloadExposures)
		case "NET002":
			affected = checkExternallyExposedWithoutPolicy(workloadExposures)
		case "NET003":
			affected = checkAllowAllIngress(g, opts)
		case "NET004":
			affected = checkAllowAllEgress(g, opts)
		case "NET005":
			affected = checkWideCIDR(g, opts)
		case "NET006":
			affected = checkNoIngressPolicy(workloadExposures)
		case "NET007":
			affected = checkNoEgressPolicy(workloadExposures)
		case "NET008":
			affected = checkHostNetworkExposed(workloadExposures)
		}

		if len(affected) > 0 {
			finding := NetworkPolicyFinding{
				CheckID:     check.ID,
				Category:    check.Category,
				Severity:    check.Severity,
				Title:       check.Name,
				Description: check.Description,
				Affected:    affected,
				Remediation: check.Remediation,
			}
			result.Findings = append(result.Findings, finding)
			result.TotalFindings += len(affected)

			switch check.Severity {
			case graph.SeverityCritical:
				result.Summary.Critical++
			case graph.SeverityHigh:
				result.Summary.High++
			case graph.SeverityMedium:
				result.Summary.Medium++
			case graph.SeverityLow:
				result.Summary.Low++
			}

			result.Summary.ByCategory[check.Category] += len(affected)
		}
	}

	sortNetworkFindingsBySeverity(result.Findings)
	return result
}

type workloadNetworkInfo struct {
	Workload            *graph.Node
	NetworkPolicies     []string
	HasIngressPolicy    bool
	HasEgressPolicy     bool
	HasAnyPolicy        bool
	IsExternallyExposed bool
	UsesHostNetwork     bool
	Services            []serviceInfo
}

type serviceInfo struct {
	Name string
	Type string
}

func analyzeWorkloadNetwork(g *graph.Graph, workload *graph.Node) *workloadNetworkInfo {
	info := &workloadNetworkInfo{
		Workload: workload,
	}

	// Check for host network
	if workload.Metadata.PodSecurityContext != nil {
		info.UsesHostNetwork = workload.Metadata.PodSecurityContext.HostNetwork
	}

	// Find network policies that apply to this workload
	for _, np := range g.GetNodesByType(graph.NodeNetworkPolicy) {
		if np.Namespace != workload.Namespace {
			continue
		}
		if np.Metadata.NetworkPolicy == nil {
			continue
		}
		if matchLabels(workload.Labels, np.Metadata.NetworkPolicy.PodSelector) {
			info.NetworkPolicies = append(info.NetworkPolicies, np.Name)
			info.HasAnyPolicy = true

			for _, pt := range np.Metadata.NetworkPolicy.PolicyTypes {
				if pt == "Ingress" {
					info.HasIngressPolicy = true
				}
				if pt == "Egress" {
					info.HasEgressPolicy = true
				}
			}
		}
	}

	// Find services that expose this workload
	for _, svc := range g.GetNodesByType(graph.NodeService) {
		if svc.Namespace != workload.Namespace {
			continue
		}
		if svc.Metadata.ServiceInfo == nil {
			continue
		}
		if matchLabels(workload.Labels, svc.Metadata.ServiceInfo.Selector) {
			info.Services = append(info.Services, serviceInfo{
				Name: svc.Name,
				Type: svc.Metadata.ServiceInfo.ServiceType,
			})
			if svc.Metadata.ServiceInfo.ServiceType == "LoadBalancer" ||
				svc.Metadata.ServiceInfo.ServiceType == "NodePort" {
				info.IsExternallyExposed = true
			}
		}
	}

	return info
}

func matchLabels(workloadLabels, selector map[string]string) bool {
	if len(selector) == 0 {
		return true
	}
	for k, v := range selector {
		if workloadLabels[k] != v {
			return false
		}
	}
	return true
}

func checkNoNetworkPolicy(exposures map[string]*workloadNetworkInfo) []AffectedNetworkResource {
	var affected []AffectedNetworkResource
	for _, info := range exposures {
		if !info.HasAnyPolicy && !info.UsesHostNetwork {
			var services []string
			for _, s := range info.Services {
				services = append(services, fmt.Sprintf("%s (%s)", s.Name, s.Type))
			}
			affected = append(affected, AffectedNetworkResource{
				Kind:      info.Workload.Metadata.WorkloadKind,
				Namespace: info.Workload.Namespace,
				Name:      info.Workload.Name,
				Details:   "No network policy applies to this workload",
				Services:  services,
			})
		}
	}
	return affected
}

func checkExternallyExposedWithoutPolicy(exposures map[string]*workloadNetworkInfo) []AffectedNetworkResource {
	var affected []AffectedNetworkResource
	for _, info := range exposures {
		if info.IsExternallyExposed && !info.HasAnyPolicy {
			var services []string
			for _, s := range info.Services {
				if s.Type == "LoadBalancer" || s.Type == "NodePort" {
					services = append(services, fmt.Sprintf("%s (%s)", s.Name, s.Type))
				}
			}
			affected = append(affected, AffectedNetworkResource{
				Kind:      info.Workload.Metadata.WorkloadKind,
				Namespace: info.Workload.Namespace,
				Name:      info.Workload.Name,
				Details:   "Externally exposed without network policy protection",
				Services:  services,
			})
		}
	}
	return affected
}

func checkAllowAllIngress(g *graph.Graph, opts NetworkPolicyOptions) []AffectedNetworkResource {
	var affected []AffectedNetworkResource
	for _, np := range g.GetNodesByType(graph.NodeNetworkPolicy) {
		if !opts.IncludeSystem && isSystemNamespace(np.Namespace) {
			continue
		}
		if opts.Namespace != "" && np.Namespace != opts.Namespace {
			continue
		}
		if np.Metadata.NetworkPolicy != nil && np.Metadata.NetworkPolicy.AllowAllIngress {
			affected = append(affected, AffectedNetworkResource{
				Kind:      "NetworkPolicy",
				Namespace: np.Namespace,
				Name:      np.Name,
				Details:   "Allows ingress from all sources",
			})
		}
	}
	return affected
}

func checkAllowAllEgress(g *graph.Graph, opts NetworkPolicyOptions) []AffectedNetworkResource {
	var affected []AffectedNetworkResource
	for _, np := range g.GetNodesByType(graph.NodeNetworkPolicy) {
		if !opts.IncludeSystem && isSystemNamespace(np.Namespace) {
			continue
		}
		if opts.Namespace != "" && np.Namespace != opts.Namespace {
			continue
		}
		if np.Metadata.NetworkPolicy != nil && np.Metadata.NetworkPolicy.AllowAllEgress {
			affected = append(affected, AffectedNetworkResource{
				Kind:      "NetworkPolicy",
				Namespace: np.Namespace,
				Name:      np.Name,
				Details:   "Allows egress to all destinations",
			})
		}
	}
	return affected
}

func checkWideCIDR(g *graph.Graph, opts NetworkPolicyOptions) []AffectedNetworkResource {
	var affected []AffectedNetworkResource
	wideCIDRs := []string{"0.0.0.0/0", "::/0", "10.0.0.0/8", "172.16.0.0/12", "192.168.0.0/16"}

	for _, np := range g.GetNodesByType(graph.NodeNetworkPolicy) {
		if !opts.IncludeSystem && isSystemNamespace(np.Namespace) {
			continue
		}
		if opts.Namespace != "" && np.Namespace != opts.Namespace {
			continue
		}
		if np.Metadata.NetworkPolicy == nil {
			continue
		}

		for _, rule := range np.Metadata.NetworkPolicy.IngressRules {
			if rule.FromIPBlock != "" && isWideCIDR(rule.FromIPBlock, wideCIDRs) {
				affected = append(affected, AffectedNetworkResource{
					Kind:      "NetworkPolicy",
					Namespace: np.Namespace,
					Name:      np.Name,
					Details:   fmt.Sprintf("Ingress allows wide CIDR: %s", rule.FromIPBlock),
				})
			}
		}

		for _, rule := range np.Metadata.NetworkPolicy.EgressRules {
			if rule.ToIPBlock != "" && isWideCIDR(rule.ToIPBlock, wideCIDRs) {
				affected = append(affected, AffectedNetworkResource{
					Kind:      "NetworkPolicy",
					Namespace: np.Namespace,
					Name:      np.Name,
					Details:   fmt.Sprintf("Egress allows wide CIDR: %s", rule.ToIPBlock),
				})
			}
		}
	}
	return affected
}

func isWideCIDR(cidr string, wideList []string) bool {
	for _, wide := range wideList {
		if cidr == wide {
			return true
		}
	}
	// Also check for /0 to /8 ranges
	if strings.Contains(cidr, "/0") || strings.Contains(cidr, "/8") {
		return true
	}
	return false
}

func checkNoIngressPolicy(exposures map[string]*workloadNetworkInfo) []AffectedNetworkResource {
	var affected []AffectedNetworkResource
	for _, info := range exposures {
		if info.HasEgressPolicy && !info.HasIngressPolicy {
			affected = append(affected, AffectedNetworkResource{
				Kind:      info.Workload.Metadata.WorkloadKind,
				Namespace: info.Workload.Namespace,
				Name:      info.Workload.Name,
				Details:   fmt.Sprintf("Has egress policy via %s but no ingress policy", strings.Join(info.NetworkPolicies, ", ")),
			})
		}
	}
	return affected
}

func checkNoEgressPolicy(exposures map[string]*workloadNetworkInfo) []AffectedNetworkResource {
	var affected []AffectedNetworkResource
	for _, info := range exposures {
		if info.HasIngressPolicy && !info.HasEgressPolicy {
			affected = append(affected, AffectedNetworkResource{
				Kind:      info.Workload.Metadata.WorkloadKind,
				Namespace: info.Workload.Namespace,
				Name:      info.Workload.Name,
				Details:   fmt.Sprintf("Has ingress policy via %s but no egress policy", strings.Join(info.NetworkPolicies, ", ")),
			})
		}
	}
	return affected
}

func checkHostNetworkExposed(exposures map[string]*workloadNetworkInfo) []AffectedNetworkResource {
	var affected []AffectedNetworkResource
	for _, info := range exposures {
		if info.UsesHostNetwork {
			affected = append(affected, AffectedNetworkResource{
				Kind:      info.Workload.Metadata.WorkloadKind,
				Namespace: info.Workload.Namespace,
				Name:      info.Workload.Name,
				Details:   "Uses host network - network policies are bypassed",
			})
		}
	}
	return affected
}

func sortNetworkFindingsBySeverity(findings []NetworkPolicyFinding) {
	severityOrder := map[graph.Severity]int{
		graph.SeverityCritical: 0,
		graph.SeverityHigh:     1,
		graph.SeverityMedium:   2,
		graph.SeverityLow:      3,
	}

	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if severityOrder[findings[i].Severity] > severityOrder[findings[j].Severity] {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}
