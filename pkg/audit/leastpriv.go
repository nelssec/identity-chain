package audit

import (
	"fmt"
	"sort"
	"strings"
	"time"
)

type LeastPrivilegeRole struct {
	ServiceAccount string
	Namespace      string
	Name           string
	RoleName       string
	RoleKind       string
	Rules          []PolicyRule
	YAML           string
	Reduction      RoleReduction
}

type PolicyRule struct {
	APIGroups   []string
	Resources   []string
	Verbs       []string
	Namespace   string
	ResourceNames []string
}

type RoleReduction struct {
	OriginalPermissions int
	NewPermissions      int
	PercentReduction    float64
	RemovedVerbs        []string
	RemovedResources    []string
}

func (a *Analyzer) GenerateLeastPrivilegeRoles() []LeastPrivilegeRole {
	var roles []LeastPrivilegeRole

	report := a.GetUsageReport()
	granted := a.extractGrantedPermissions()

	grantedBySA := make(map[string][]GrantedPermission)
	for _, p := range granted {
		grantedBySA[p.ServiceAccount] = append(grantedBySA[p.ServiceAccount], p)
	}

	for saKey, usage := range report.SAUsage {
		role := a.generateRoleForSA(saKey, usage, grantedBySA[saKey])
		if role != nil {
			roles = append(roles, *role)
		}
	}

	sort.Slice(roles, func(i, j int) bool {
		return roles[i].Reduction.PercentReduction > roles[j].Reduction.PercentReduction
	})

	return roles
}

func (a *Analyzer) generateRoleForSA(saKey string, usage *ServiceAccountUsage, granted []GrantedPermission) *LeastPrivilegeRole {
	if usage == nil || len(usage.Resources) == 0 {
		return nil
	}

	ns := extractNamespace(saKey)
	name := extractSAName(saKey)

	rulesByNS := make(map[string]map[string]map[string]bool)

	for _, resUsage := range usage.Resources {
		resNS := resUsage.Namespace
		if resNS == "" {
			resNS = "*"
		}

		if rulesByNS[resNS] == nil {
			rulesByNS[resNS] = make(map[string]map[string]bool)
		}

		apiGroup, resource := parseResourceWithGroup(resUsage.Resource)
		resKey := apiGroup + "/" + resource

		if rulesByNS[resNS][resKey] == nil {
			rulesByNS[resNS][resKey] = make(map[string]bool)
		}

		for verb := range resUsage.Verbs {
			rulesByNS[resNS][resKey][verb] = true
		}
	}

	var rules []PolicyRule
	isClusterScoped := false

	for resNS, resources := range rulesByNS {
		if resNS == "*" || resNS == "" {
			isClusterScoped = true
		}

		for resKey, verbs := range resources {
			parts := strings.SplitN(resKey, "/", 2)
			apiGroup := ""
			resource := resKey
			if len(parts) == 2 {
				apiGroup = parts[0]
				resource = parts[1]
			}

			var verbList []string
			for v := range verbs {
				verbList = append(verbList, v)
			}
			sort.Strings(verbList)

			rule := PolicyRule{
				APIGroups: []string{apiGroup},
				Resources: []string{resource},
				Verbs:     verbList,
				Namespace: resNS,
			}
			rules = append(rules, rule)
		}
	}

	consolidatedRules := consolidateRules(rules)

	roleKind := "Role"
	if isClusterScoped || ns == "" {
		roleKind = "ClusterRole"
	}

	roleName := fmt.Sprintf("%s-least-priv", name)

	usedPerms := countPermissions(consolidatedRules)
	grantedPerms := len(granted)
	reduction := float64(0)
	if grantedPerms > 0 {
		reduction = float64(grantedPerms-usedPerms) / float64(grantedPerms) * 100
	}

	removedVerbs, removedResources := findRemovedPermissions(granted, consolidatedRules)

	role := &LeastPrivilegeRole{
		ServiceAccount: saKey,
		Namespace:      ns,
		Name:           name,
		RoleName:       roleName,
		RoleKind:       roleKind,
		Rules:          consolidatedRules,
		Reduction: RoleReduction{
			OriginalPermissions: grantedPerms,
			NewPermissions:      usedPerms,
			PercentReduction:    reduction,
			RemovedVerbs:        removedVerbs,
			RemovedResources:    removedResources,
		},
	}

	role.YAML = generateRoleYAML(role)

	return role
}

func parseResourceWithGroup(resource string) (string, string) {
	if strings.Contains(resource, ".") {
		parts := strings.SplitN(resource, ".", 2)
		return parts[1], parts[0]
	}

	coreResources := map[string]bool{
		"pods": true, "services": true, "secrets": true, "configmaps": true,
		"endpoints": true, "persistentvolumeclaims": true, "replicationcontrollers": true,
		"serviceaccounts": true, "namespaces": true, "nodes": true,
		"persistentvolumes": true, "resourcequotas": true, "limitranges": true,
		"events": true, "bindings": true, "componentstatuses": true,
	}

	if coreResources[resource] {
		return "", resource
	}

	return "", resource
}

func consolidateRules(rules []PolicyRule) []PolicyRule {
	ruleMap := make(map[string]*PolicyRule)

	for _, rule := range rules {
		key := fmt.Sprintf("%s|%s", strings.Join(rule.APIGroups, ","), strings.Join(rule.Resources, ","))

		if existing, ok := ruleMap[key]; ok {
			verbSet := make(map[string]bool)
			for _, v := range existing.Verbs {
				verbSet[v] = true
			}
			for _, v := range rule.Verbs {
				verbSet[v] = true
			}
			var verbs []string
			for v := range verbSet {
				verbs = append(verbs, v)
			}
			sort.Strings(verbs)
			existing.Verbs = verbs
		} else {
			r := rule
			ruleMap[key] = &r
		}
	}

	var result []PolicyRule
	for _, r := range ruleMap {
		result = append(result, *r)
	}

	sort.Slice(result, func(i, j int) bool {
		if result[i].APIGroups[0] != result[j].APIGroups[0] {
			return result[i].APIGroups[0] < result[j].APIGroups[0]
		}
		return result[i].Resources[0] < result[j].Resources[0]
	})

	return result
}

func countPermissions(rules []PolicyRule) int {
	count := 0
	for _, r := range rules {
		count += len(r.Verbs) * len(r.Resources)
	}
	return count
}

func findRemovedPermissions(granted []GrantedPermission, rules []PolicyRule) ([]string, []string) {
	usedVerbs := make(map[string]bool)
	usedResources := make(map[string]bool)

	for _, r := range rules {
		for _, v := range r.Verbs {
			usedVerbs[v] = true
		}
		for _, res := range r.Resources {
			usedResources[res] = true
		}
	}

	removedVerbsMap := make(map[string]bool)
	removedResourcesMap := make(map[string]bool)

	for _, g := range granted {
		if !usedVerbs[g.Verb] {
			removedVerbsMap[g.Verb] = true
		}
		if !usedResources[g.Resource] {
			removedResourcesMap[g.Resource] = true
		}
	}

	var removedVerbs, removedResources []string
	for v := range removedVerbsMap {
		removedVerbs = append(removedVerbs, v)
	}
	for r := range removedResourcesMap {
		removedResources = append(removedResources, r)
	}
	sort.Strings(removedVerbs)
	sort.Strings(removedResources)

	return removedVerbs, removedResources
}

func generateRoleYAML(role *LeastPrivilegeRole) string {
	var sb strings.Builder

	sb.WriteString(fmt.Sprintf("apiVersion: rbac.authorization.k8s.io/v1\n"))
	sb.WriteString(fmt.Sprintf("kind: %s\n", role.RoleKind))
	sb.WriteString("metadata:\n")
	sb.WriteString(fmt.Sprintf("  name: %s\n", role.RoleName))
	if role.RoleKind == "Role" && role.Namespace != "" {
		sb.WriteString(fmt.Sprintf("  namespace: %s\n", role.Namespace))
	}
	sb.WriteString("  labels:\n")
	sb.WriteString("    generated-by: idc\n")
	sb.WriteString(fmt.Sprintf("    generated-at: \"%s\"\n", time.Now().Format(time.RFC3339)))
	sb.WriteString("rules:\n")

	for _, rule := range role.Rules {
		sb.WriteString("- apiGroups:\n")
		for _, ag := range rule.APIGroups {
			if ag == "" {
				sb.WriteString("  - \"\"\n")
			} else {
				sb.WriteString(fmt.Sprintf("  - %s\n", ag))
			}
		}
		sb.WriteString("  resources:\n")
		for _, res := range rule.Resources {
			sb.WriteString(fmt.Sprintf("  - %s\n", res))
		}
		sb.WriteString("  verbs:\n")
		for _, verb := range rule.Verbs {
			sb.WriteString(fmt.Sprintf("  - %s\n", verb))
		}
	}

	if role.RoleKind == "Role" {
		sb.WriteString("---\n")
		sb.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
		sb.WriteString("kind: RoleBinding\n")
		sb.WriteString("metadata:\n")
		sb.WriteString(fmt.Sprintf("  name: %s-binding\n", role.RoleName))
		if role.Namespace != "" {
			sb.WriteString(fmt.Sprintf("  namespace: %s\n", role.Namespace))
		}
		sb.WriteString("roleRef:\n")
		sb.WriteString("  apiGroup: rbac.authorization.k8s.io\n")
		sb.WriteString("  kind: Role\n")
		sb.WriteString(fmt.Sprintf("  name: %s\n", role.RoleName))
		sb.WriteString("subjects:\n")
		sb.WriteString("- kind: ServiceAccount\n")
		sb.WriteString(fmt.Sprintf("  name: %s\n", role.Name))
		sb.WriteString(fmt.Sprintf("  namespace: %s\n", role.Namespace))
	} else {
		sb.WriteString("---\n")
		sb.WriteString("apiVersion: rbac.authorization.k8s.io/v1\n")
		sb.WriteString("kind: ClusterRoleBinding\n")
		sb.WriteString("metadata:\n")
		sb.WriteString(fmt.Sprintf("  name: %s-binding\n", role.RoleName))
		sb.WriteString("roleRef:\n")
		sb.WriteString("  apiGroup: rbac.authorization.k8s.io\n")
		sb.WriteString("  kind: ClusterRole\n")
		sb.WriteString(fmt.Sprintf("  name: %s\n", role.RoleName))
		sb.WriteString("subjects:\n")
		sb.WriteString("- kind: ServiceAccount\n")
		sb.WriteString(fmt.Sprintf("  name: %s\n", role.Name))
		sb.WriteString(fmt.Sprintf("  namespace: %s\n", role.Namespace))
	}

	return sb.String()
}

func (a *Analyzer) GenerateLeastPrivilegeRoleForSA(serviceAccount, namespace string) *LeastPrivilegeRole {
	saKey := fmt.Sprintf("system:serviceaccount:%s:%s", namespace, serviceAccount)

	report := a.GetUsageReport()
	usage, exists := report.SAUsage[saKey]
	if !exists {
		return nil
	}

	granted := a.extractGrantedPermissions()
	var saGranted []GrantedPermission
	for _, p := range granted {
		if p.ServiceAccount == saKey {
			saGranted = append(saGranted, p)
		}
	}

	return a.generateRoleForSA(saKey, usage, saGranted)
}
