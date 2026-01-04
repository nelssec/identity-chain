package analysis

import (
	"sort"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type BlastResult struct {
	SourceWorkload  *graph.Node
	ServiceAccount  *graph.Node
	K8sResources    []ResourceAccess
	CloudRoles      []CloudAccess
	TotalK8sPerms   int
	TotalCloudPerms int
	MaxSeverity     graph.Severity
	Path            []PathStep
}

type ResourceAccess struct {
	Resource *graph.Node
	Verbs    []string
	ViaRole  string
	Severity graph.Severity
}

type CloudAccess struct {
	CloudRole    *graph.Node
	Provider     string
	RoleARN      string
	Severity     graph.Severity
	Policies     []CloudPolicy
	BlastRadius  []string
}

type CloudPolicy struct {
	Name     string
	Actions  []string
	IsAdmin  bool
	Severity graph.Severity
}

type PathStep struct {
	Node     *graph.Node
	Edge     *graph.Edge
	EdgeType graph.EdgeType
}

func BlastRadius(g *graph.Graph, workloadNodeID string) (*BlastResult, error) {
	workload := g.GetNode(workloadNodeID)
	if workload == nil {
		return nil, nil
	}

	result := &BlastResult{
		SourceWorkload: workload,
		MaxSeverity:    graph.SeverityLow,
	}

	usesEdges := g.GetOutEdges(workloadNodeID)
	var saNode *graph.Node
	for _, e := range usesEdges {
		if e.Type == graph.EdgeUses {
			saNode = g.GetNode(e.To)
			result.Path = append(result.Path, PathStep{
				Node:     saNode,
				Edge:     e,
				EdgeType: e.Type,
			})
			break
		}
	}

	if saNode == nil {
		return result, nil
	}
	result.ServiceAccount = saNode

	bindsEdges := g.GetOutEdges(saNode.ID)
	roleNodes := make(map[string]*graph.Node)

	for _, e := range bindsEdges {
		if e.Type == graph.EdgeBinds {
			roleNode := g.GetNode(e.To)
			if roleNode != nil {
				roleNodes[roleNode.ID] = roleNode
				result.Path = append(result.Path, PathStep{
					Node:     roleNode,
					Edge:     e,
					EdgeType: e.Type,
				})
			}
		}
		if e.Type == graph.EdgeAssumes {
			cloudRole := g.GetNode(e.To)
			if cloudRole != nil {
				access := CloudAccess{
					CloudRole: cloudRole,
					Provider:  e.Metadata.CloudProvider,
					RoleARN:   e.Metadata.RoleARN,
					Severity:  graph.SeverityHigh,
				}

				cloudEdges := g.GetOutEdges(cloudRole.ID)
				resourceTypes := make(map[string][]string)
				for _, ce := range cloudEdges {
					if ce.Type == graph.EdgeAllows {
						resourceNode := g.GetNode(ce.To)
						if resourceNode != nil {
							resType := resourceNode.Metadata.ResourceType
							if resType == "" {
								resType = "resource"
							}
							resourceTypes[resType] = append(resourceTypes[resType], ce.Metadata.Verbs...)
						}
					}
				}

				for resType, actions := range resourceTypes {
					access.BlastRadius = append(access.BlastRadius, describeCloudAccess(e.Metadata.CloudProvider, resType, actions))
				}

				if len(cloudRole.Metadata.CloudPolicies) > 0 {
					for _, cp := range cloudRole.Metadata.CloudPolicies {
						policy := CloudPolicy{
							Name:     cp.Name,
							IsAdmin:  cp.IsAdmin,
							Severity: graph.SeverityHigh,
						}
						for _, stmt := range cp.Statements {
							policy.Actions = append(policy.Actions, stmt.Actions...)
						}
						if cp.IsAdmin {
							policy.Severity = graph.SeverityCritical
							access.Severity = graph.SeverityCritical
						}
						access.Policies = append(access.Policies, policy)

						for _, stmt := range cp.Statements {
							blastDesc := describeActualPolicyImpact(cp.Name, stmt.Actions, stmt.Resources)
							if blastDesc != "" {
								access.BlastRadius = append(access.BlastRadius, blastDesc)
							}
						}
					}
				} else if len(cloudRole.Metadata.PolicyARNs) > 0 {
					for _, policyARN := range cloudRole.Metadata.PolicyARNs {
						policyName := shortARN(policyARN)
						policy := CloudPolicy{
							Name:     policyName,
							Severity: graph.SeverityHigh,
						}
						access.Policies = append(access.Policies, policy)
						access.BlastRadius = append(access.BlastRadius, describePolicyImpact(policyName))
					}
				}

				if len(access.BlastRadius) == 0 {
					access.BlastRadius = inferBlastRadiusFromRoleName(cloudRole.Name, e.Metadata.CloudProvider)
				}

				result.CloudRoles = append(result.CloudRoles, access)
				result.TotalCloudPerms++
				result.Path = append(result.Path, PathStep{
					Node:     cloudRole,
					Edge:     e,
					EdgeType: e.Type,
				})
				updateMaxSeverity(result, access.Severity)
			}
		}
	}

	for _, roleNode := range roleNodes {
		grantsEdges := g.GetOutEdges(roleNode.ID)
		for _, e := range grantsEdges {
			if e.Type == graph.EdgeGrants {
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				severity := graph.ClassifyEdgeSeverity(e, resourceNode)
				access := ResourceAccess{
					Resource: resourceNode,
					Verbs:    e.Metadata.Verbs,
					ViaRole:  roleNode.Name,
					Severity: severity,
				}
				result.K8sResources = append(result.K8sResources, access)
				result.TotalK8sPerms += len(e.Metadata.Verbs)
				updateMaxSeverity(result, severity)
			}
		}
	}

	sortResourcesBySeverity(result.K8sResources)

	return result, nil
}

func BlastRadiusFromSA(g *graph.Graph, saNamespace, saName string) (*BlastResult, error) {
	saNodeID := graph.GenerateNodeID(graph.NodeServiceAccount, saNamespace, saName)
	saNode := g.GetNode(saNodeID)
	if saNode == nil {
		return nil, nil
	}

	result := &BlastResult{
		ServiceAccount: saNode,
		MaxSeverity:    graph.SeverityLow,
	}

	workloads := g.GetWorkloadsUsingSA(saNodeID)
	if len(workloads) > 0 {
		result.SourceWorkload = workloads[0]
	}

	bindsEdges := g.GetOutEdges(saNodeID)
	roleNodes := make(map[string]*graph.Node)

	for _, e := range bindsEdges {
		if e.Type == graph.EdgeBinds {
			roleNode := g.GetNode(e.To)
			if roleNode != nil {
				roleNodes[roleNode.ID] = roleNode
			}
		}
		if e.Type == graph.EdgeAssumes {
			cloudRole := g.GetNode(e.To)
			if cloudRole != nil {
				access := CloudAccess{
					CloudRole: cloudRole,
					Provider:  e.Metadata.CloudProvider,
					RoleARN:   e.Metadata.RoleARN,
					Severity:  graph.SeverityHigh,
				}
				result.CloudRoles = append(result.CloudRoles, access)
				result.TotalCloudPerms++
				updateMaxSeverity(result, access.Severity)
			}
		}
	}

	for _, roleNode := range roleNodes {
		grantsEdges := g.GetOutEdges(roleNode.ID)
		for _, e := range grantsEdges {
			if e.Type == graph.EdgeGrants {
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				severity := graph.ClassifyEdgeSeverity(e, resourceNode)
				access := ResourceAccess{
					Resource: resourceNode,
					Verbs:    e.Metadata.Verbs,
					ViaRole:  roleNode.Name,
					Severity: severity,
				}
				result.K8sResources = append(result.K8sResources, access)
				result.TotalK8sPerms += len(e.Metadata.Verbs)
				updateMaxSeverity(result, severity)
			}
		}
	}

	sortResourcesBySeverity(result.K8sResources)

	return result, nil
}

func updateMaxSeverity(r *BlastResult, s graph.Severity) {
	severityOrder := map[graph.Severity]int{
		graph.SeverityLow:      0,
		graph.SeverityMedium:   1,
		graph.SeverityHigh:     2,
		graph.SeverityCritical: 3,
	}
	if severityOrder[s] > severityOrder[r.MaxSeverity] {
		r.MaxSeverity = s
	}
}

func describeActualPolicyImpact(policyName string, actions []string, resources []string) string {
	if len(actions) == 0 {
		return ""
	}

	serviceActions := make(map[string][]string)
	hasWildcard := false
	hasWrite := false
	hasRead := false

	for _, action := range actions {
		if action == "*" {
			hasWildcard = true
			continue
		}
		parts := splitAction(action)
		if len(parts) == 2 {
			service := parts[0]
			verb := parts[1]
			serviceActions[service] = append(serviceActions[service], verb)

			if verb == "*" || containsAny(verb, "Put", "Create", "Delete", "Update", "Write", "Modify", "Set") {
				hasWrite = true
			}
			if containsAny(verb, "Get", "List", "Describe", "Read") {
				hasRead = true
			}
		}
	}

	resourceScope := describeResourceScope(resources)

	if hasWildcard {
		return "FULL ADMIN: All actions on " + resourceScope
	}

	var descriptions []string
	for service, verbs := range serviceActions {
		svcDesc := describeServiceAccess(service, verbs, resources)
		if svcDesc != "" {
			descriptions = append(descriptions, svcDesc)
		}
	}

	if len(descriptions) == 0 {
		accessLevel := "Access"
		if hasWrite && hasRead {
			accessLevel = "Read/Write access"
		} else if hasWrite {
			accessLevel = "Write access"
		} else if hasRead {
			accessLevel = "Read access"
		}
		return accessLevel + " via " + policyName + " to " + resourceScope
	}

	if len(descriptions) == 1 {
		return descriptions[0]
	}
	return descriptions[0] + " (+" + formatInt(len(descriptions)-1) + " more services)"
}

func splitAction(action string) []string {
	for i := 0; i < len(action); i++ {
		if action[i] == ':' {
			return []string{action[:i], action[i+1:]}
		}
	}
	return []string{action}
}

func formatInt(n int) string {
	if n < 10 {
		return string('0' + byte(n))
	}
	return formatInt(n/10) + string('0'+byte(n%10))
}

func describeResourceScope(resources []string) string {
	if len(resources) == 0 {
		return "unspecified resources"
	}

	allWildcard := true
	for _, r := range resources {
		if r != "*" {
			allWildcard = false
			break
		}
	}

	if allWildcard {
		return "ALL resources in the account"
	}

	for _, r := range resources {
		if len(r) > 4 && r[:4] == "arn:" {
			parts := splitARN(r)
			if len(parts) >= 6 {
				service := parts[2]
				resource := parts[5]
				if resource == "*" {
					return "ALL " + describeServiceName(service) + " resources"
				}
				return "specific " + describeServiceName(service) + " resources"
			}
		}
	}

	if len(resources) == 1 {
		return resources[0]
	}
	return formatInt(len(resources)) + " specific resources"
}

func splitARN(arn string) []string {
	var parts []string
	current := ""
	for _, c := range arn {
		if c == ':' {
			parts = append(parts, current)
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func describeServiceName(service string) string {
	names := map[string]string{
		"s3":             "S3 bucket",
		"secretsmanager": "Secrets Manager",
		"ssm":            "Systems Manager",
		"kms":            "KMS key",
		"dynamodb":       "DynamoDB",
		"rds":            "RDS database",
		"ec2":            "EC2",
		"lambda":         "Lambda",
		"iam":            "IAM",
		"sts":            "STS",
		"sqs":            "SQS",
		"sns":            "SNS",
		"eks":            "EKS",
	}
	if name, ok := names[service]; ok {
		return name
	}
	return service
}

func describeServiceAccess(service string, verbs []string, resources []string) string {
	hasWildcard := false
	hasWrite := false
	hasRead := false
	hasAdmin := false

	for _, v := range verbs {
		if v == "*" {
			hasWildcard = true
		}
		if containsAny(v, "Put", "Create", "Delete", "Update", "Write", "Modify", "Set") {
			hasWrite = true
		}
		if containsAny(v, "Get", "List", "Describe", "Read") {
			hasRead = true
		}
		if containsAny(v, "CreateRole", "AttachRolePolicy", "PutRolePolicy", "PassRole") {
			hasAdmin = true
		}
	}

	scope := describeResourceScope(resources)
	serviceName := describeServiceName(service)

	if hasWildcard {
		return "FULL " + serviceName + " access to " + scope
	}
	if hasAdmin {
		return "ADMIN-level " + serviceName + " permissions (can modify IAM) on " + scope
	}
	if hasWrite && hasRead {
		return "Read/Write " + serviceName + " access to " + scope
	}
	if hasWrite {
		return "Write " + serviceName + " access to " + scope
	}
	if hasRead {
		return "Read " + serviceName + " access to " + scope
	}
	return serviceName + " access (" + joinVerbs(verbs, 3) + ") to " + scope
}

func joinVerbs(verbs []string, max int) string {
	if len(verbs) <= max {
		result := ""
		for i, v := range verbs {
			if i > 0 {
				result += ", "
			}
			result += v
		}
		return result
	}
	result := ""
	for i := 0; i < max; i++ {
		if i > 0 {
			result += ", "
		}
		result += verbs[i]
	}
	return result + ", ..."
}

func describePolicyImpact(policyName string) string {
	policyLower := toLower(policyName)

	if contains(policyLower, "admin") {
		return "FULL ADMIN access to AWS account"
	}
	if contains(policyLower, "s3") {
		if contains(policyLower, "fullaccess") || contains(policyLower, "full") {
			return "Read/Write access to ALL S3 buckets in the account"
		}
		if contains(policyLower, "readonly") || contains(policyLower, "read") {
			return "Read access to ALL S3 buckets in the account"
		}
		return "Access to S3 storage"
	}
	if contains(policyLower, "secretsmanager") || contains(policyLower, "secrets") {
		if contains(policyLower, "readwrite") || contains(policyLower, "full") {
			return "Read/Write access to ALL secrets in Secrets Manager"
		}
		if contains(policyLower, "readonly") || contains(policyLower, "read") {
			return "Read access to ALL secrets in Secrets Manager"
		}
		return "Access to Secrets Manager"
	}
	if contains(policyLower, "ec2") {
		if contains(policyLower, "fullaccess") || contains(policyLower, "full") {
			return "FULL access to EC2 instances - can launch, terminate, modify"
		}
		if contains(policyLower, "readonly") || contains(policyLower, "read") {
			return "Read access to EC2 instances"
		}
		return "Access to EC2 compute"
	}
	if contains(policyLower, "iam") {
		if contains(policyLower, "fullaccess") || contains(policyLower, "full") {
			return "FULL IAM access - can create roles, policies, users (CRITICAL)"
		}
		if contains(policyLower, "readonly") || contains(policyLower, "read") {
			return "Read access to IAM configuration"
		}
		return "Access to IAM"
	}
	if contains(policyLower, "rds") || contains(policyLower, "database") {
		return "Access to RDS databases"
	}
	if contains(policyLower, "dynamodb") {
		return "Access to DynamoDB tables"
	}
	if contains(policyLower, "lambda") {
		return "Access to Lambda functions"
	}
	if contains(policyLower, "kms") {
		return "Access to KMS encryption keys"
	}
	if contains(policyLower, "sqs") {
		return "Access to SQS message queues"
	}
	if contains(policyLower, "sns") {
		return "Access to SNS notifications"
	}
	if contains(policyLower, "cloudwatch") {
		return "Access to CloudWatch monitoring"
	}
	if contains(policyLower, "eks") || contains(policyLower, "kubernetes") {
		return "Access to EKS/Kubernetes resources"
	}
	if contains(policyLower, "ssm") {
		return "Access to Systems Manager and parameters"
	}

	return "Access to AWS resources via " + policyName
}

func inferBlastRadiusFromRoleName(roleName, provider string) []string {
	var impacts []string
	roleLower := toLower(roleName)

	if contains(roleLower, "admin") {
		impacts = append(impacts, "Potential admin-level access (check policies)")
	}
	if contains(roleLower, "s3") {
		impacts = append(impacts, "Likely access to S3 storage")
	}
	if contains(roleLower, "secret") {
		impacts = append(impacts, "Likely access to secrets/credentials")
	}
	if contains(roleLower, "database") || contains(roleLower, "rds") || contains(roleLower, "db") {
		impacts = append(impacts, "Likely access to databases")
	}

	if len(impacts) == 0 {
		impacts = append(impacts, "Cloud IAM role - check attached policies for specific access")
	}

	return impacts
}

func toLower(s string) string {
	result := make([]byte, len(s))
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c >= 'A' && c <= 'Z' {
			result[i] = c + 32
		} else {
			result[i] = c
		}
	}
	return string(result)
}

func contains(s, substr string) bool {
	if len(substr) > len(s) {
		return false
	}
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}

func describeCloudAccess(provider, resourceType string, actions []string) string {
	hasWrite := false
	hasRead := false
	hasAdmin := false

	for _, action := range actions {
		if action == "*" || action == "*:*" {
			hasAdmin = true
		}
		if containsAny(action, "Put", "Create", "Delete", "Update", "Write", "Modify") {
			hasWrite = true
		}
		if containsAny(action, "Get", "List", "Describe", "Read") {
			hasRead = true
		}
	}

	accessLevel := "access"
	if hasAdmin {
		accessLevel = "FULL ADMIN access to"
	} else if hasWrite && hasRead {
		accessLevel = "Read/Write access to"
	} else if hasWrite {
		accessLevel = "Write access to"
	} else if hasRead {
		accessLevel = "Read access to"
	}

	resourceDesc := resourceType
	switch resourceType {
	case "s3", "s3-bucket", "storage-account":
		resourceDesc = "S3 buckets / object storage"
	case "secretsmanager", "secrets-manager", "key-vault":
		resourceDesc = "secrets and credentials"
	case "kms", "key-management":
		resourceDesc = "encryption keys"
	case "iam", "iam-resource":
		resourceDesc = "IAM policies and roles"
	case "ec2", "virtual-machine", "compute":
		resourceDesc = "compute instances"
	case "rds", "sql-database", "database":
		resourceDesc = "databases"
	case "lambda", "function":
		resourceDesc = "serverless functions"
	case "sqs", "sns", "service-bus", "messaging":
		resourceDesc = "messaging queues"
	case "dynamodb", "cosmos-db", "nosql":
		resourceDesc = "NoSQL databases"
	case "cloudformation", "arm-template":
		resourceDesc = "infrastructure templates"
	}

	return accessLevel + " " + resourceDesc
}

func containsAny(s string, substrs ...string) bool {
	for _, sub := range substrs {
		if len(s) >= len(sub) {
			for i := 0; i <= len(s)-len(sub); i++ {
				if s[i:i+len(sub)] == sub {
					return true
				}
			}
		}
	}
	return false
}

func shortARN(arn string) string {
	parts := make([]string, 0)
	current := ""
	for _, c := range arn {
		if c == '/' || c == ':' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return arn
}

func sortResourcesBySeverity(resources []ResourceAccess) {
	severityOrder := map[graph.Severity]int{
		graph.SeverityCritical: 0,
		graph.SeverityHigh:     1,
		graph.SeverityMedium:   2,
		graph.SeverityLow:      3,
	}
	sort.Slice(resources, func(i, j int) bool {
		return severityOrder[resources[i].Severity] < severityOrder[resources[j].Severity]
	})
}

func AllWorkloadBlastRadius(g *graph.Graph) ([]*BlastResult, error) {
	workloads := g.GetNodesByType(graph.NodeWorkload)
	results := make([]*BlastResult, 0, len(workloads))

	for _, w := range workloads {
		result, err := BlastRadius(g, w.ID)
		if err != nil {
			continue
		}
		if result != nil {
			results = append(results, result)
		}
	}

	sort.Slice(results, func(i, j int) bool {
		severityOrder := map[graph.Severity]int{
			graph.SeverityCritical: 0,
			graph.SeverityHigh:     1,
			graph.SeverityMedium:   2,
			graph.SeverityLow:      3,
		}
		return severityOrder[results[i].MaxSeverity] < severityOrder[results[j].MaxSeverity]
	})

	return results, nil
}

type SAAnalysis struct {
	ServiceAccount   *graph.Node
	Workloads        []*graph.Node
	Roles            []*graph.Node
	K8sResources     []ResourceAccess
	CloudRoles       []CloudAccess
	TotalPermissions int
	MaxSeverity      graph.Severity
	RiskFactors      []RiskFactor
	IsOverprivileged bool
	InUse            bool
}

type RiskFactor struct {
	Category    string
	Description string
	Severity    graph.Severity
}

func AnalyzeAllServiceAccounts(g *graph.Graph) ([]*SAAnalysis, error) {
	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	results := make([]*SAAnalysis, 0, len(serviceAccounts))

	for _, sa := range serviceAccounts {
		analysis := AnalyzeServiceAccount(g, sa)
		results = append(results, analysis)
	}

	sort.Slice(results, func(i, j int) bool {
		severityOrder := map[graph.Severity]int{
			graph.SeverityCritical: 0,
			graph.SeverityHigh:     1,
			graph.SeverityMedium:   2,
			graph.SeverityLow:      3,
		}
		if severityOrder[results[i].MaxSeverity] != severityOrder[results[j].MaxSeverity] {
			return severityOrder[results[i].MaxSeverity] < severityOrder[results[j].MaxSeverity]
		}
		return results[i].TotalPermissions > results[j].TotalPermissions
	})

	return results, nil
}

func AnalyzeServiceAccount(g *graph.Graph, sa *graph.Node) *SAAnalysis {
	analysis := &SAAnalysis{
		ServiceAccount: sa,
		MaxSeverity:    graph.SeverityLow,
		RiskFactors:    make([]RiskFactor, 0),
	}

	analysis.Workloads = g.GetWorkloadsUsingSA(sa.ID)
	analysis.InUse = len(analysis.Workloads) > 0

	bindsEdges := g.GetOutEdges(sa.ID)
	roleNodes := make(map[string]*graph.Node)

	for _, e := range bindsEdges {
		if e.Type == graph.EdgeBinds {
			roleNode := g.GetNode(e.To)
			if roleNode != nil {
				roleNodes[roleNode.ID] = roleNode
				analysis.Roles = append(analysis.Roles, roleNode)
			}
		}
		if e.Type == graph.EdgeAssumes {
			cloudRole := g.GetNode(e.To)
			if cloudRole != nil {
				access := CloudAccess{
					CloudRole: cloudRole,
					Provider:  e.Metadata.CloudProvider,
					RoleARN:   e.Metadata.RoleARN,
					Severity:  graph.SeverityHigh,
				}
				analysis.CloudRoles = append(analysis.CloudRoles, access)
				analysis.RiskFactors = append(analysis.RiskFactors, RiskFactor{
					Category:    "Cloud Access",
					Description: "Can assume cloud role: " + e.Metadata.RoleARN,
					Severity:    graph.SeverityHigh,
				})
				updateSAMaxSeverity(analysis, graph.SeverityHigh)
			}
		}
	}

	hasSecretsAccess := false
	hasWildcardVerbs := false
	hasClusterWide := false
	hasPodExec := false
	hasRBACModify := false

	for _, roleNode := range roleNodes {
		if roleNode.Metadata.IsClusterRole {
			hasClusterWide = true
		}

		grantsEdges := g.GetOutEdges(roleNode.ID)
		for _, e := range grantsEdges {
			if e.Type == graph.EdgeGrants {
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				severity := graph.ClassifyEdgeSeverity(e, resourceNode)
				access := ResourceAccess{
					Resource: resourceNode,
					Verbs:    e.Metadata.Verbs,
					ViaRole:  roleNode.Name,
					Severity: severity,
				}
				analysis.K8sResources = append(analysis.K8sResources, access)
				analysis.TotalPermissions += len(e.Metadata.Verbs)
				updateSAMaxSeverity(analysis, severity)

				if resourceNode.Metadata.ResourceKind == "secrets" {
					hasSecretsAccess = true
				}
				if resourceNode.Metadata.ResourceKind == "pods/exec" {
					hasPodExec = true
				}
				if resourceNode.Metadata.ResourceKind == "roles" || resourceNode.Metadata.ResourceKind == "clusterroles" ||
					resourceNode.Metadata.ResourceKind == "rolebindings" || resourceNode.Metadata.ResourceKind == "clusterrolebindings" {
					for _, v := range e.Metadata.Verbs {
						if v == "create" || v == "update" || v == "patch" || v == "*" {
							hasRBACModify = true
							break
						}
					}
				}

				for _, v := range e.Metadata.Verbs {
					if v == "*" {
						hasWildcardVerbs = true
						break
					}
				}
			}
		}
	}

	if hasSecretsAccess {
		analysis.RiskFactors = append(analysis.RiskFactors, RiskFactor{
			Category:    "Secrets Access",
			Description: "Can read secrets - potential credential exposure",
			Severity:    graph.SeverityCritical,
		})
	}

	if hasWildcardVerbs {
		analysis.RiskFactors = append(analysis.RiskFactors, RiskFactor{
			Category:    "Wildcard Permissions",
			Description: "Has wildcard (*) verb permissions",
			Severity:    graph.SeverityHigh,
		})
	}

	if hasClusterWide {
		analysis.RiskFactors = append(analysis.RiskFactors, RiskFactor{
			Category:    "Cluster-Wide Access",
			Description: "Has cluster-scoped permissions via ClusterRole",
			Severity:    graph.SeverityHigh,
		})
	}

	if hasPodExec {
		analysis.RiskFactors = append(analysis.RiskFactors, RiskFactor{
			Category:    "Pod Exec",
			Description: "Can exec into pods - lateral movement risk",
			Severity:    graph.SeverityHigh,
		})
	}

	if hasRBACModify {
		analysis.RiskFactors = append(analysis.RiskFactors, RiskFactor{
			Category:    "RBAC Modification",
			Description: "Can modify RBAC - privilege escalation risk",
			Severity:    graph.SeverityCritical,
		})
	}

	if len(analysis.CloudRoles) > 0 {
		analysis.RiskFactors = append(analysis.RiskFactors, RiskFactor{
			Category:    "Cloud Identity",
			Description: "Has cloud IAM access - blast radius extends to cloud",
			Severity:    graph.SeverityHigh,
		})
	}

	analysis.IsOverprivileged = len(analysis.RiskFactors) > 0 ||
		analysis.TotalPermissions > 20 ||
		analysis.MaxSeverity == graph.SeverityCritical ||
		analysis.MaxSeverity == graph.SeverityHigh

	sortResourcesBySeverity(analysis.K8sResources)

	return analysis
}

func updateSAMaxSeverity(a *SAAnalysis, s graph.Severity) {
	severityOrder := map[graph.Severity]int{
		graph.SeverityLow:      0,
		graph.SeverityMedium:   1,
		graph.SeverityHigh:     2,
		graph.SeverityCritical: 3,
	}
	if severityOrder[s] > severityOrder[a.MaxSeverity] {
		a.MaxSeverity = s
	}
}
