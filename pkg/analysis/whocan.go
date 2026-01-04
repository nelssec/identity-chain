package analysis

import (
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// WhoCanResult represents subjects that can perform an action
type WhoCanResult struct {
	Verb            string
	Resource        string
	ResourceName    string
	Namespace       string
	Subjects        []Subject
	TotalCount      int
	ClusterWideOnly bool
}

// Subject represents an identity that can perform an action
type Subject struct {
	Kind            string // ServiceAccount, User, Group
	Name            string
	Namespace       string
	ViaRole         string
	IsClusterRole   bool
	ViaBinding      string
	Workloads       []*graph.Node
	Severity        graph.Severity
	IsSystemSubject bool
}

// WhoCanQuery defines what action to search for
type WhoCanQuery struct {
	Verb         string
	Resource     string
	ResourceName string
	Namespace    string
	APIGroup     string
	Subresource  string
}

// WhoCan finds all subjects that can perform a given action
func WhoCan(g *graph.Graph, query WhoCanQuery) (*WhoCanResult, error) {
	result := &WhoCanResult{
		Verb:         query.Verb,
		Resource:     query.Resource,
		ResourceName: query.ResourceName,
		Namespace:    query.Namespace,
	}

	// Build a map of all roles and their permissions
	rolePermissions := buildRolePermissionMap(g)

	// Find all roles that grant the requested permission
	matchingRoles := findMatchingRoles(rolePermissions, query)

	// Find all subjects bound to these roles
	subjects := findSubjectsForRoles(g, matchingRoles, query.Namespace)

	// Deduplicate and enrich subjects
	result.Subjects = deduplicateSubjects(subjects)
	result.TotalCount = len(result.Subjects)

	// Sort by severity, then by name
	sort.Slice(result.Subjects, func(i, j int) bool {
		if severityRank[result.Subjects[i].Severity] != severityRank[result.Subjects[j].Severity] {
			return severityRank[result.Subjects[i].Severity] < severityRank[result.Subjects[j].Severity]
		}
		return result.Subjects[i].Name < result.Subjects[j].Name
	})

	return result, nil
}

// WhoCanAccessSecret is a convenience function for finding secret access
func WhoCanAccessSecret(g *graph.Graph, namespace, secretName string) (*WhoCanResult, error) {
	return WhoCan(g, WhoCanQuery{
		Verb:         "get",
		Resource:     "secrets",
		ResourceName: secretName,
		Namespace:    namespace,
	})
}

// WhoCanExecPods finds who can exec into pods
func WhoCanExecPods(g *graph.Graph, namespace string) (*WhoCanResult, error) {
	return WhoCan(g, WhoCanQuery{
		Verb:        "create",
		Resource:    "pods",
		Subresource: "exec",
		Namespace:   namespace,
	})
}

// WhoCanDeletePods finds who can delete pods
func WhoCanDeletePods(g *graph.Graph, namespace string) (*WhoCanResult, error) {
	return WhoCan(g, WhoCanQuery{
		Verb:      "delete",
		Resource:  "pods",
		Namespace: namespace,
	})
}

// WhoCanCreateClusterRoleBindings finds who can create cluster role bindings
func WhoCanCreateClusterRoleBindings(g *graph.Graph) (*WhoCanResult, error) {
	return WhoCan(g, WhoCanQuery{
		Verb:     "create",
		Resource: "clusterrolebindings",
		APIGroup: "rbac.authorization.k8s.io",
	})
}

// RolePermission holds a role's permissions
type RolePermission struct {
	RoleNode      *graph.Node
	Resources     []string
	Verbs         []string
	ResourceNames []string
	APIGroups     []string
	IsClusterRole bool
	Namespace     string
}

func buildRolePermissionMap(g *graph.Graph) map[string][]RolePermission {
	permissions := make(map[string][]RolePermission)

	roles := g.GetNodesByType(graph.NodeRole)
	for _, role := range roles {
		edges := g.GetOutEdges(role.ID)
		for _, e := range edges {
			if e.Type != graph.EdgeGrants {
				continue
			}
			resourceNode := g.GetNode(e.To)
			if resourceNode == nil {
				continue
			}

			perm := RolePermission{
				RoleNode:      role,
				Resources:     []string{resourceNode.Metadata.ResourceKind},
				Verbs:         e.Metadata.Verbs,
				ResourceNames: e.Metadata.ResourceNames,
				IsClusterRole: role.Metadata.IsClusterRole,
				Namespace:     role.Namespace,
			}

			permissions[role.ID] = append(permissions[role.ID], perm)
		}
	}

	return permissions
}

func findMatchingRoles(rolePerms map[string][]RolePermission, query WhoCanQuery) []*graph.Node {
	var matches []*graph.Node
	seen := make(map[string]bool)

	for roleID, perms := range rolePerms {
		for _, perm := range perms {
			if matchesQuery(perm, query) {
				if !seen[roleID] {
					matches = append(matches, perm.RoleNode)
					seen[roleID] = true
				}
			}
		}
	}

	return matches
}

func matchesQuery(perm RolePermission, query WhoCanQuery) bool {
	// Check verb match
	verbMatch := false
	for _, v := range perm.Verbs {
		if v == "*" || v == query.Verb {
			verbMatch = true
			break
		}
	}
	if !verbMatch {
		return false
	}

	// Check resource match
	resourceMatch := false
	queryResource := query.Resource
	if query.Subresource != "" {
		queryResource = query.Resource + "/" + query.Subresource
	}

	for _, r := range perm.Resources {
		if r == "*" || r == queryResource {
			resourceMatch = true
			break
		}
		// Handle subresource wildcards like pods/*
		if strings.HasSuffix(r, "/*") {
			baseResource := strings.TrimSuffix(r, "/*")
			if strings.HasPrefix(queryResource, baseResource+"/") || queryResource == baseResource {
				resourceMatch = true
				break
			}
		}
	}
	if !resourceMatch {
		return false
	}

	// Check resource name if specified in query
	if query.ResourceName != "" && len(perm.ResourceNames) > 0 {
		nameMatch := false
		for _, rn := range perm.ResourceNames {
			if rn == query.ResourceName {
				nameMatch = true
				break
			}
		}
		if !nameMatch {
			return false
		}
	}

	// Check namespace scope if query is namespace-scoped
	if query.Namespace != "" && !perm.IsClusterRole {
		if perm.Namespace != query.Namespace {
			return false
		}
	}

	return true
}

func findSubjectsForRoles(g *graph.Graph, roles []*graph.Node, namespace string) []Subject {
	var subjects []Subject

	// Build a map of roles by ID for quick lookup
	roleSet := make(map[string]*graph.Node)
	for _, r := range roles {
		roleSet[r.ID] = r
	}

	// Find all ServiceAccounts and check their bindings
	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		// If namespace specified and this is a different namespace, skip (unless cluster-scoped)
		if namespace != "" && sa.Namespace != namespace {
			// Still might be bound via ClusterRoleBinding, check below
		}

		edges := g.GetOutEdges(sa.ID)
		for _, e := range edges {
			if e.Type != graph.EdgeBinds {
				continue
			}

			role, exists := roleSet[e.To]
			if !exists {
				continue
			}

			// Skip if namespace-scoped and different namespace
			if namespace != "" && !role.Metadata.IsClusterRole && sa.Namespace != namespace {
				continue
			}

			workloads := g.GetWorkloadsUsingSA(sa.ID)

			subject := Subject{
				Kind:          "ServiceAccount",
				Name:          sa.Name,
				Namespace:     sa.Namespace,
				ViaRole:       role.Name,
				IsClusterRole: role.Metadata.IsClusterRole,
				ViaBinding:    e.Metadata.BindingName,
				Workloads:     workloads,
				Severity:      determinSubjectSeverity(sa, role),
			}

			// Check if this is a system service account
			if strings.HasPrefix(sa.Name, "system:") || sa.Namespace == "kube-system" {
				subject.IsSystemSubject = true
			}

			subjects = append(subjects, subject)
		}
	}

	return subjects
}

func determinSubjectSeverity(sa *graph.Node, role *graph.Node) graph.Severity {
	// System components get low severity (expected)
	if sa.Namespace == "kube-system" {
		return graph.SeverityLow
	}

	// ClusterRoles with dangerous names
	if role.Metadata.IsClusterRole {
		nameLower := strings.ToLower(role.Name)
		if strings.Contains(nameLower, "admin") || strings.Contains(nameLower, "cluster-admin") {
			return graph.SeverityCritical
		}
		return graph.SeverityHigh
	}

	return graph.SeverityMedium
}

func deduplicateSubjects(subjects []Subject) []Subject {
	seen := make(map[string]int) // key -> index in result
	var result []Subject

	for _, s := range subjects {
		key := s.Kind + ":" + s.Namespace + "/" + s.Name
		if idx, exists := seen[key]; exists {
			// Merge workloads
			existing := &result[idx]
			existing.Workloads = append(existing.Workloads, s.Workloads...)
			// Keep the higher severity
			if severityValue[s.Severity] > severityValue[existing.Severity] {
				existing.Severity = s.Severity
			}
		} else {
			seen[key] = len(result)
			result = append(result, s)
		}
	}

	return result
}

// ReverseRBACQuery represents what we want to know about a subject
type ReverseRBACQuery struct {
	SubjectKind string
	SubjectName string
	Namespace   string
}

// ReverseRBACResult shows all permissions for a subject
type ReverseRBACResult struct {
	Subject     string
	Namespace   string
	Permissions []PermissionGrant
	Roles       []*graph.Node
	TotalVerbs  int
	MaxSeverity graph.Severity
}

// PermissionGrant represents a single permission granted
type PermissionGrant struct {
	Resource      string
	Verbs         []string
	ViaRole       string
	IsClusterRole bool
	Namespace     string
	Severity      graph.Severity
}

// WhatCan returns all permissions for a given subject
func WhatCan(g *graph.Graph, query ReverseRBACQuery) (*ReverseRBACResult, error) {
	result := &ReverseRBACResult{
		Subject:     query.SubjectName,
		Namespace:   query.Namespace,
		MaxSeverity: graph.SeverityLow,
	}

	// Find the service account node
	var saNode *graph.Node
	if query.SubjectKind == "ServiceAccount" || query.SubjectKind == "" {
		saNodeID := graph.GenerateNodeID(graph.NodeServiceAccount, query.Namespace, query.SubjectName)
		saNode = g.GetNode(saNodeID)
	}

	if saNode == nil {
		return result, nil
	}

	// Find all roles bound to this SA
	edges := g.GetOutEdges(saNode.ID)
	for _, e := range edges {
		if e.Type != graph.EdgeBinds {
			continue
		}

		role := g.GetNode(e.To)
		if role == nil {
			continue
		}

		result.Roles = append(result.Roles, role)

		// Get all permissions from this role
		roleEdges := g.GetOutEdges(role.ID)
		for _, re := range roleEdges {
			if re.Type != graph.EdgeGrants {
				continue
			}

			resourceNode := g.GetNode(re.To)
			if resourceNode == nil {
				continue
			}

			severity := graph.ClassifyEdgeSeverity(re, resourceNode)
			perm := PermissionGrant{
				Resource:      resourceNode.Metadata.ResourceKind,
				Verbs:         re.Metadata.Verbs,
				ViaRole:       role.Name,
				IsClusterRole: role.Metadata.IsClusterRole,
				Namespace:     role.Namespace,
				Severity:      severity,
			}

			result.Permissions = append(result.Permissions, perm)
			result.TotalVerbs += len(re.Metadata.Verbs)

			if severityValue[severity] > severityValue[result.MaxSeverity] {
				result.MaxSeverity = severity
			}
		}
	}

	// Sort by severity
	sort.Slice(result.Permissions, func(i, j int) bool {
		return severityRank[result.Permissions[i].Severity] < severityRank[result.Permissions[j].Severity]
	})

	return result, nil
}

// AccessMatrix generates a matrix of subjects x resources
type AccessMatrix struct {
	Subjects  []string
	Resources []string
	Matrix    map[string]map[string][]string // subject -> resource -> verbs
}

// GenerateAccessMatrix creates a full access matrix for a namespace
func GenerateAccessMatrix(g *graph.Graph, namespace string) (*AccessMatrix, error) {
	matrix := &AccessMatrix{
		Matrix: make(map[string]map[string][]string),
	}

	subjectSet := make(map[string]bool)
	resourceSet := make(map[string]bool)

	// Find all service accounts
	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if namespace != "" && sa.Namespace != namespace {
			continue
		}

		subjectKey := sa.Namespace + "/" + sa.Name
		subjectSet[subjectKey] = true

		if matrix.Matrix[subjectKey] == nil {
			matrix.Matrix[subjectKey] = make(map[string][]string)
		}

		// Get all permissions
		edges := g.GetOutEdges(sa.ID)
		for _, e := range edges {
			if e.Type != graph.EdgeBinds {
				continue
			}

			role := g.GetNode(e.To)
			if role == nil {
				continue
			}

			roleEdges := g.GetOutEdges(role.ID)
			for _, re := range roleEdges {
				if re.Type != graph.EdgeGrants {
					continue
				}

				resourceNode := g.GetNode(re.To)
				if resourceNode == nil {
					continue
				}

				resource := resourceNode.Metadata.ResourceKind
				resourceSet[resource] = true

				// Merge verbs
				existing := matrix.Matrix[subjectKey][resource]
				for _, v := range re.Metadata.Verbs {
					if !containsString(existing, v) {
						existing = append(existing, v)
					}
				}
				matrix.Matrix[subjectKey][resource] = existing
			}
		}
	}

	// Convert sets to sorted slices
	for s := range subjectSet {
		matrix.Subjects = append(matrix.Subjects, s)
	}
	sort.Strings(matrix.Subjects)

	for r := range resourceSet {
		matrix.Resources = append(matrix.Resources, r)
	}
	sort.Strings(matrix.Resources)

	return matrix, nil
}
