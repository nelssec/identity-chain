package checks

import (
	"fmt"
	"os"
	"regexp"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
	"gopkg.in/yaml.v3"
)

type CustomCheckConfig struct {
	Checks []CustomCheck `yaml:"checks"`
}

type CustomCheck struct {
	ID          string            `yaml:"id"`
	Name        string            `yaml:"name"`
	Description string            `yaml:"description"`
	Severity    string            `yaml:"severity"`
	Category    string            `yaml:"category"`
	Remediation string            `yaml:"remediation,omitempty"`
	Match       MatchCriteria     `yaml:"match"`
	Condition   CheckCondition    `yaml:"condition"`
	Metadata    map[string]string `yaml:"metadata,omitempty"`
}

type MatchCriteria struct {
	Kind             string            `yaml:"kind"`
	Namespace        string            `yaml:"namespace,omitempty"`
	NamespacePattern string            `yaml:"namespacePattern,omitempty"`
	NamePattern      string            `yaml:"namePattern,omitempty"`
	Labels           map[string]string `yaml:"labels,omitempty"`
}

type CheckCondition struct {
	Exists               *bool             `yaml:"exists,omitempty"`
	NotExists            *bool             `yaml:"notExists,omitempty"`
	HasLabel             string            `yaml:"hasLabel,omitempty"`
	MissingLabel         string            `yaml:"missingLabel,omitempty"`
	LabelEquals          map[string]string `yaml:"labelEquals,omitempty"`
	LabelNotEquals       map[string]string `yaml:"labelNotEquals,omitempty"`
	HasSecurityContext   *SecurityContext  `yaml:"hasSecurityContext,omitempty"`
	MissingSecurityField string            `yaml:"missingSecurityField,omitempty"`
	HasCloudIdentity     *bool             `yaml:"hasCloudIdentity,omitempty"`
	HasRBACBinding       *bool             `yaml:"hasRBACBinding,omitempty"`
	BindsToRole          string            `yaml:"bindsToRole,omitempty"`
	IsClusterRole        *bool             `yaml:"isClusterRole,omitempty"`
	CountGreaterThan     *int              `yaml:"countGreaterThan,omitempty"`
	CountLessThan        *int              `yaml:"countLessThan,omitempty"`
	And                  []CheckCondition  `yaml:"and,omitempty"`
	Or                   []CheckCondition  `yaml:"or,omitempty"`
	Not                  *CheckCondition   `yaml:"not,omitempty"`
}

type SecurityContext struct {
	Privileged               *bool    `yaml:"privileged,omitempty"`
	HostNetwork              *bool    `yaml:"hostNetwork,omitempty"`
	HostPID                  *bool    `yaml:"hostPID,omitempty"`
	HostIPC                  *bool    `yaml:"hostIPC,omitempty"`
	RunAsRoot                *bool    `yaml:"runAsRoot,omitempty"`
	AllowPrivilegeEscalation *bool    `yaml:"allowPrivilegeEscalation,omitempty"`
	HasCapability            []string `yaml:"hasCapability,omitempty"`
	HasHostPath              *bool    `yaml:"hasHostPath,omitempty"`
}

type CustomFinding struct {
	CheckID     string
	Name        string
	Category    string
	Severity    string
	Description string
	Remediation string
	Affected    []AffectedResource
	Metadata    map[string]string
}

type AffectedResource struct {
	Kind      string
	Namespace string
	Name      string
	Details   string
}

func LoadCustomChecks(path string) (*CustomCheckConfig, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, fmt.Errorf("failed to read config file: %w", err)
	}

	var config CustomCheckConfig
	if err := yaml.Unmarshal(data, &config); err != nil {
		return nil, fmt.Errorf("failed to parse config: %w", err)
	}

	for i, check := range config.Checks {
		if check.ID == "" {
			return nil, fmt.Errorf("check %d: missing id", i)
		}
		if check.Name == "" {
			return nil, fmt.Errorf("check %s: missing name", check.ID)
		}
		if check.Match.Kind == "" {
			return nil, fmt.Errorf("check %s: missing match.kind", check.ID)
		}
	}

	return &config, nil
}

func RunCustomChecks(g *graph.Graph, config *CustomCheckConfig) []CustomFinding {
	var findings []CustomFinding

	for _, check := range config.Checks {
		checkFindings := runCheck(g, check)
		findings = append(findings, checkFindings...)
	}

	return findings
}

func runCheck(g *graph.Graph, check CustomCheck) []CustomFinding {
	var findings []CustomFinding

	matchedNodes := matchNodes(g, check.Match)

	if check.Condition.Exists != nil && *check.Condition.Exists {
		for _, node := range matchedNodes {
			findings = append(findings, createFinding(check, node, "Resource exists matching criteria"))
		}
		return findings
	}

	if check.Condition.NotExists != nil && *check.Condition.NotExists {
		if len(matchedNodes) == 0 {
			findings = append(findings, CustomFinding{
				CheckID:     check.ID,
				Name:        check.Name,
				Category:    check.Category,
				Severity:    check.Severity,
				Description: check.Description,
				Remediation: check.Remediation,
				Affected: []AffectedResource{{
					Kind:    check.Match.Kind,
					Details: "No matching resources found",
				}},
				Metadata: check.Metadata,
			})
		}
		return findings
	}

	for _, node := range matchedNodes {
		if evaluateCondition(g, node, check.Condition) {
			details := getConditionDetails(check.Condition)
			findings = append(findings, createFinding(check, node, details))
		}
	}

	if check.Condition.CountGreaterThan != nil {
		if len(matchedNodes) > *check.Condition.CountGreaterThan {
			findings = append(findings, CustomFinding{
				CheckID:     check.ID,
				Name:        check.Name,
				Category:    check.Category,
				Severity:    check.Severity,
				Description: check.Description,
				Remediation: check.Remediation,
				Affected: []AffectedResource{{
					Kind:    check.Match.Kind,
					Details: fmt.Sprintf("Count %d exceeds threshold %d", len(matchedNodes), *check.Condition.CountGreaterThan),
				}},
				Metadata: check.Metadata,
			})
		}
	}

	if check.Condition.CountLessThan != nil {
		if len(matchedNodes) < *check.Condition.CountLessThan {
			findings = append(findings, CustomFinding{
				CheckID:     check.ID,
				Name:        check.Name,
				Category:    check.Category,
				Severity:    check.Severity,
				Description: check.Description,
				Remediation: check.Remediation,
				Affected: []AffectedResource{{
					Kind:    check.Match.Kind,
					Details: fmt.Sprintf("Count %d below threshold %d", len(matchedNodes), *check.Condition.CountLessThan),
				}},
				Metadata: check.Metadata,
			})
		}
	}

	return findings
}

func matchNodes(g *graph.Graph, match MatchCriteria) []*graph.Node {
	var matched []*graph.Node

	nodeType := kindToNodeType(match.Kind)
	nodes := g.GetNodesByType(nodeType)

	for _, node := range nodes {
		if matchesNamespace(node, match) && matchesName(node, match) &&
			matchesLabels(node, match.Labels) {
			matched = append(matched, node)
		}
	}

	return matched
}

func kindToNodeType(kind string) graph.NodeType {
	switch strings.ToLower(kind) {
	case "workload", "pod", "deployment", "statefulset", "daemonset", "job", "cronjob":
		return graph.NodeWorkload
	case "serviceaccount", "sa":
		return graph.NodeServiceAccount
	case "role", "clusterrole":
		return graph.NodeRole
	case "cloudrole":
		return graph.NodeCloudRole
	case "scc":
		return graph.NodeSCC
	case "networkpolicy":
		return graph.NodeNetworkPolicy
	case "service":
		return graph.NodeService
	default:
		return graph.NodeWorkload
	}
}

func matchesNamespace(node *graph.Node, match MatchCriteria) bool {
	if match.Namespace == "" && match.NamespacePattern == "" {
		return true
	}

	if match.Namespace != "" && node.Namespace != match.Namespace {
		return false
	}

	if match.NamespacePattern != "" {
		re, err := regexp.Compile(match.NamespacePattern)
		if err != nil {
			return false
		}
		if !re.MatchString(node.Namespace) {
			return false
		}
	}

	return true
}

func matchesName(node *graph.Node, match MatchCriteria) bool {
	if match.NamePattern == "" {
		return true
	}

	re, err := regexp.Compile(match.NamePattern)
	if err != nil {
		return false
	}
	return re.MatchString(node.Name)
}

func matchesLabels(node *graph.Node, requiredLabels map[string]string) bool {
	if len(requiredLabels) == 0 {
		return true
	}

	for k, v := range requiredLabels {
		if node.Labels[k] != v {
			return false
		}
	}
	return true
}

func evaluateCondition(g *graph.Graph, node *graph.Node, cond CheckCondition) bool {
	if len(cond.And) > 0 {
		for _, c := range cond.And {
			if !evaluateCondition(g, node, c) {
				return false
			}
		}
		return true
	}

	if len(cond.Or) > 0 {
		for _, c := range cond.Or {
			if evaluateCondition(g, node, c) {
				return true
			}
		}
		return false
	}

	if cond.Not != nil {
		return !evaluateCondition(g, node, *cond.Not)
	}

	if cond.HasLabel != "" {
		_, ok := node.Labels[cond.HasLabel]
		return ok
	}

	if cond.MissingLabel != "" {
		_, ok := node.Labels[cond.MissingLabel]
		return !ok
	}

	if len(cond.LabelEquals) > 0 {
		for k, v := range cond.LabelEquals {
			if node.Labels[k] != v {
				return false
			}
		}
		return true
	}

	if len(cond.LabelNotEquals) > 0 {
		for k, v := range cond.LabelNotEquals {
			if node.Labels[k] == v {
				return false
			}
		}
		return true
	}

	if cond.HasSecurityContext != nil {
		return checkSecurityContext(node, cond.HasSecurityContext)
	}

	if cond.MissingSecurityField != "" {
		return checkMissingSecurityField(node, cond.MissingSecurityField)
	}

	if cond.HasCloudIdentity != nil {
		hasCloud := node.Metadata.CloudRoleARN != "" || node.Metadata.GCPServiceAccount != "" || node.Metadata.AzureManagedID != ""
		return hasCloud == *cond.HasCloudIdentity
	}

	if cond.HasRBACBinding != nil {
		edges := g.GetOutEdges(node.ID)
		hasBinding := false
		for _, e := range edges {
			if e.Type == graph.EdgeBinds {
				hasBinding = true
				break
			}
		}
		return hasBinding == *cond.HasRBACBinding
	}

	if cond.BindsToRole != "" {
		edges := g.GetOutEdges(node.ID)
		for _, e := range edges {
			if e.Type == graph.EdgeBinds {
				targetNode := g.GetNode(e.To)
				if targetNode != nil && targetNode.Name == cond.BindsToRole {
					return true
				}
			}
		}
		return false
	}

	if cond.IsClusterRole != nil {
		return node.Metadata.IsClusterRole == *cond.IsClusterRole
	}

	return false
}

func checkSecurityContext(node *graph.Node, sc *SecurityContext) bool {
	psc := node.Metadata.PodSecurityContext
	if psc == nil {
		return false
	}

	if sc.HostNetwork != nil && psc.HostNetwork != *sc.HostNetwork {
		return false
	}
	if sc.HostPID != nil && psc.HostPID != *sc.HostPID {
		return false
	}
	if sc.HostIPC != nil && psc.HostIPC != *sc.HostIPC {
		return false
	}
	if sc.HasHostPath != nil {
		hasHostPath := len(psc.HostPaths) > 0
		if hasHostPath != *sc.HasHostPath {
			return false
		}
	}

	for _, container := range psc.Containers {
		if sc.Privileged != nil && container.Privileged == *sc.Privileged {
			return true
		}
		if sc.RunAsRoot != nil && container.RunAsRoot == *sc.RunAsRoot {
			return true
		}
		if sc.AllowPrivilegeEscalation != nil && container.AllowPrivilegeEscalation == *sc.AllowPrivilegeEscalation {
			return true
		}
		if len(sc.HasCapability) > 0 {
			capSet := make(map[string]bool)
			for _, c := range container.Capabilities {
				capSet[c] = true
			}
			allFound := true
			for _, c := range sc.HasCapability {
				if !capSet[c] {
					allFound = false
					break
				}
			}
			if allFound {
				return true
			}
		}
	}

	if sc.Privileged == nil && sc.RunAsRoot == nil && sc.AllowPrivilegeEscalation == nil && len(sc.HasCapability) == 0 {
		return true
	}

	return false
}

func checkMissingSecurityField(node *graph.Node, field string) bool {
	psc := node.Metadata.PodSecurityContext
	if psc == nil {
		return true
	}

	switch strings.ToLower(field) {
	case "runasnonroot":
		for _, c := range psc.Containers {
			if !c.RunAsRoot && c.HasSecurityContext {
				return false
			}
		}
		return true
	case "readonlyrootfilesystem":
		for _, c := range psc.Containers {
			if c.ReadOnlyRootFilesystem {
				return false
			}
		}
		return true
	case "securitycontext":
		for _, c := range psc.Containers {
			if c.HasSecurityContext {
				return false
			}
		}
		return true
	case "capabilities":
		for _, c := range psc.Containers {
			if len(c.Capabilities) > 0 {
				return false
			}
		}
		return true
	default:
		return false
	}
}

func createFinding(check CustomCheck, node *graph.Node, details string) CustomFinding {
	return CustomFinding{
		CheckID:     check.ID,
		Name:        check.Name,
		Category:    check.Category,
		Severity:    check.Severity,
		Description: check.Description,
		Remediation: check.Remediation,
		Affected: []AffectedResource{{
			Kind:      string(node.Type),
			Namespace: node.Namespace,
			Name:      node.Name,
			Details:   details,
		}},
		Metadata: check.Metadata,
	}
}

func getConditionDetails(cond CheckCondition) string {
	if cond.MissingLabel != "" {
		return fmt.Sprintf("Missing label: %s", cond.MissingLabel)
	}
	if cond.HasSecurityContext != nil {
		return "Security context matches condition"
	}
	if cond.MissingSecurityField != "" {
		return fmt.Sprintf("Missing security field: %s", cond.MissingSecurityField)
	}
	if cond.HasCloudIdentity != nil {
		if *cond.HasCloudIdentity {
			return "Has cloud identity binding"
		}
		return "Missing cloud identity binding"
	}
	if cond.BindsToRole != "" {
		return fmt.Sprintf("Binds to role: %s", cond.BindsToRole)
	}
	return "Condition matched"
}
