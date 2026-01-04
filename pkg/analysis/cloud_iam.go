package analysis

import (
	"regexp"
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// CloudIAMFinding represents a security finding in cloud IAM configuration
type CloudIAMFinding struct {
	Provider    string
	Category    CloudFindingCategory
	Severity    graph.Severity
	Title       string
	Description string
	RoleARN     string
	AccountID   string
	Details     map[string]interface{}
	Remediation string
}

// CloudFindingCategory categorizes cloud IAM findings
type CloudFindingCategory string

const (
	CloudCategoryPrivEsc       CloudFindingCategory = "privilege_escalation"
	CloudCategoryCrossAccount  CloudFindingCategory = "cross_account"
	CloudCategoryOverPermissive CloudFindingCategory = "over_permissive"
	CloudCategoryTrustPolicy   CloudFindingCategory = "trust_policy"
	CloudCategoryAdminAccess   CloudFindingCategory = "admin_access"
	CloudCategoryDataExposure  CloudFindingCategory = "data_exposure"
)

// CloudIAMAuditResult holds all cloud IAM findings
type CloudIAMAuditResult struct {
	Findings          []CloudIAMFinding
	Summary           CloudIAMSummary
	AnalyzedRoles     int
	CrossAccountRoles int
}

// CloudIAMSummary provides statistics
type CloudIAMSummary struct {
	Critical    int
	High        int
	Medium      int
	Low         int
	ByProvider  map[string]int
	ByCategory  map[CloudFindingCategory]int
}

// AnalyzeCloudIAM performs comprehensive cloud IAM security analysis
func AnalyzeCloudIAM(g *graph.Graph) *CloudIAMAuditResult {
	result := &CloudIAMAuditResult{
		Summary: CloudIAMSummary{
			ByProvider: make(map[string]int),
			ByCategory: make(map[CloudFindingCategory]int),
		},
	}

	cloudRoles := g.GetNodesByType(graph.NodeCloudRole)
	result.AnalyzedRoles = len(cloudRoles)

	for _, role := range cloudRoles {
		findings := analyzeCloudRole(g, role)
		result.Findings = append(result.Findings, findings...)
	}

	// Update summary
	for _, f := range result.Findings {
		switch f.Severity {
		case graph.SeverityCritical:
			result.Summary.Critical++
		case graph.SeverityHigh:
			result.Summary.High++
		case graph.SeverityMedium:
			result.Summary.Medium++
		case graph.SeverityLow:
			result.Summary.Low++
		}
		result.Summary.ByProvider[f.Provider]++
		result.Summary.ByCategory[f.Category]++
	}

	// Sort by severity
	sort.Slice(result.Findings, func(i, j int) bool {
		return severityRank[result.Findings[i].Severity] < severityRank[result.Findings[j].Severity]
	})

	return result
}

func analyzeCloudRole(g *graph.Graph, role *graph.Node) []CloudIAMFinding {
	var findings []CloudIAMFinding

	provider := role.Metadata.CloudProvider
	roleARN := role.Metadata.CloudRoleARN

	// Check for admin policies
	findings = append(findings, checkAdminPolicies(role)...)

	// Check for privilege escalation paths
	findings = append(findings, checkCloudPrivEsc(role)...)

	// Check for cross-account access
	findings = append(findings, checkCrossAccountAccess(role, roleARN)...)

	// Check for overly permissive policies
	findings = append(findings, checkOverlyPermissive(role)...)

	// Check for sensitive data access
	findings = append(findings, checkSensitiveDataAccess(g, role)...)

	// Set provider and role ARN on all findings
	for i := range findings {
		findings[i].Provider = provider
		findings[i].RoleARN = roleARN
	}

	return findings
}

func checkAdminPolicies(role *graph.Node) []CloudIAMFinding {
	var findings []CloudIAMFinding

	for _, policy := range role.Metadata.CloudPolicies {
		if policy.IsAdmin {
			findings = append(findings, CloudIAMFinding{
				Category:    CloudCategoryAdminAccess,
				Severity:    graph.SeverityCritical,
				Title:       "Admin Policy Attached",
				Description: "Role has administrator-level access to the cloud account",
				Details: map[string]interface{}{
					"policy_name": policy.Name,
					"policy_arn":  policy.ARN,
				},
				Remediation: "Replace with least-privilege policies specific to workload needs",
			})
		}

		// Check for IAM privilege escalation
		for _, stmt := range policy.Statements {
			if hasIAMPrivEsc(stmt.Actions) {
				findings = append(findings, CloudIAMFinding{
					Category:    CloudCategoryPrivEsc,
					Severity:    graph.SeverityCritical,
					Title:       "IAM Privilege Escalation Risk",
					Description: "Role can modify IAM policies or create new roles",
					Details: map[string]interface{}{
						"policy_name":       policy.Name,
						"dangerous_actions": filterIAMActions(stmt.Actions),
					},
					Remediation: "Remove IAM modification permissions unless absolutely required",
				})
			}
		}
	}

	return findings
}

func checkCloudPrivEsc(role *graph.Node) []CloudIAMFinding {
	var findings []CloudIAMFinding

	dangerousCombinations := []struct {
		actions     []string
		title       string
		description string
		severity    graph.Severity
	}{
		{
			actions:     []string{"iam:CreateRole", "iam:AttachRolePolicy", "sts:AssumeRole"},
			title:       "Can Create and Assume Roles",
			description: "Can create new IAM roles and assume them for privilege escalation",
			severity:    graph.SeverityCritical,
		},
		{
			actions:     []string{"iam:PassRole", "ec2:RunInstances"},
			title:       "EC2 Instance Role Assumption",
			description: "Can launch EC2 instances with any role, assuming those permissions",
			severity:    graph.SeverityCritical,
		},
		{
			actions:     []string{"iam:PassRole", "lambda:CreateFunction", "lambda:InvokeFunction"},
			title:       "Lambda Role Assumption",
			description: "Can create Lambda functions with any role and invoke them",
			severity:    graph.SeverityCritical,
		},
		{
			actions:     []string{"iam:PassRole", "ecs:RunTask"},
			title:       "ECS Task Role Assumption",
			description: "Can run ECS tasks with any role",
			severity:    graph.SeverityHigh,
		},
		{
			actions:     []string{"iam:CreatePolicyVersion"},
			title:       "Policy Version Backdoor",
			description: "Can create new policy versions, potentially escalating permissions",
			severity:    graph.SeverityCritical,
		},
		{
			actions:     []string{"iam:SetDefaultPolicyVersion"},
			title:       "Policy Version Switch",
			description: "Can switch active policy version to a more permissive one",
			severity:    graph.SeverityHigh,
		},
		{
			actions:     []string{"iam:CreateLoginProfile"},
			title:       "Console Access Creation",
			description: "Can create console login for IAM users",
			severity:    graph.SeverityHigh,
		},
		{
			actions:     []string{"iam:UpdateAssumeRolePolicy"},
			title:       "Trust Policy Modification",
			description: "Can modify role trust policies to allow new principals",
			severity:    graph.SeverityCritical,
		},
		{
			actions:     []string{"iam:CreateAccessKey"},
			title:       "Access Key Creation",
			description: "Can create access keys for IAM users",
			severity:    graph.SeverityHigh,
		},
		{
			actions:     []string{"ssm:StartSession"},
			title:       "SSM Session Manager Access",
			description: "Can start SSM sessions to EC2 instances",
			severity:    graph.SeverityHigh,
		},
		{
			actions:     []string{"ssm:SendCommand"},
			title:       "SSM Command Execution",
			description: "Can execute commands on SSM-managed instances",
			severity:    graph.SeverityCritical,
		},
		{
			actions:     []string{"glue:UpdateDevEndpoint"},
			title:       "Glue Dev Endpoint SSH Key Injection",
			description: "Can inject SSH keys into Glue dev endpoints",
			severity:    graph.SeverityHigh,
		},
		{
			actions:     []string{"cloudformation:CreateStack", "iam:PassRole"},
			title:       "CloudFormation Role Assumption",
			description: "Can create CloudFormation stacks with any role",
			severity:    graph.SeverityCritical,
		},
	}

	allActions := collectAllActions(role)

	for _, combo := range dangerousCombinations {
		if hasAllActions(allActions, combo.actions) {
			findings = append(findings, CloudIAMFinding{
				Category:    CloudCategoryPrivEsc,
				Severity:    combo.severity,
				Title:       combo.title,
				Description: combo.description,
				Details: map[string]interface{}{
					"matched_actions": combo.actions,
				},
				Remediation: "Remove or restrict the dangerous permission combination",
			})
		}
	}

	return findings
}

func checkCrossAccountAccess(role *graph.Node, roleARN string) []CloudIAMFinding {
	var findings []CloudIAMFinding

	accountID := extractAccountFromARN(roleARN)
	if accountID == "" {
		return findings
	}

	for _, policy := range role.Metadata.CloudPolicies {
		for _, stmt := range policy.Statements {
			for _, resource := range stmt.Resources {
				// Check for cross-account resource access
				resourceAccount := extractAccountFromARN(resource)
				if resourceAccount != "" && resourceAccount != accountID && resourceAccount != "*" {
					findings = append(findings, CloudIAMFinding{
						Category:    CloudCategoryCrossAccount,
						Severity:    graph.SeverityHigh,
						Title:       "Cross-Account Resource Access",
						Description: "Role can access resources in a different AWS account",
						Details: map[string]interface{}{
							"source_account": accountID,
							"target_account": resourceAccount,
							"resource":       resource,
							"actions":        stmt.Actions,
						},
						Remediation: "Verify cross-account access is intentional and properly secured",
					})
				}

				// Check for wildcard account access
				if resource == "*" && hasHighRiskActions(stmt.Actions) {
					findings = append(findings, CloudIAMFinding{
						Category:    CloudCategoryOverPermissive,
						Severity:    graph.SeverityCritical,
						Title:       "Wildcard Resource Access",
						Description: "Role has access to all resources with dangerous actions",
						Details: map[string]interface{}{
							"actions":  stmt.Actions,
							"resource": resource,
						},
						Remediation: "Restrict resource scope to specific ARNs",
					})
				}
			}
		}
	}

	return findings
}

func checkOverlyPermissive(role *graph.Node) []CloudIAMFinding {
	var findings []CloudIAMFinding

	for _, policy := range role.Metadata.CloudPolicies {
		for _, stmt := range policy.Statements {
			// Check for Action: "*"
			for _, action := range stmt.Actions {
				if action == "*" {
					findings = append(findings, CloudIAMFinding{
						Category:    CloudCategoryOverPermissive,
						Severity:    graph.SeverityCritical,
						Title:       "Wildcard Action Permission",
						Description: "Policy allows all actions (Action: *)",
						Details: map[string]interface{}{
							"policy_name": policy.Name,
							"resources":   stmt.Resources,
						},
						Remediation: "Replace Action: * with specific required actions",
					})
				}
			}

			// Check for service wildcards like s3:*
			for _, action := range stmt.Actions {
				if strings.HasSuffix(action, ":*") {
					service := strings.TrimSuffix(action, ":*")
					if isHighRiskService(service) {
						findings = append(findings, CloudIAMFinding{
							Category:    CloudCategoryOverPermissive,
							Severity:    graph.SeverityHigh,
							Title:       "Service Wildcard Permission",
							Description: "Policy allows all actions for a sensitive service",
							Details: map[string]interface{}{
								"policy_name": policy.Name,
								"service":     service,
								"action":      action,
							},
							Remediation: "Replace service:* with specific required actions",
						})
					}
				}
			}
		}
	}

	return findings
}

func checkSensitiveDataAccess(g *graph.Graph, role *graph.Node) []CloudIAMFinding {
	var findings []CloudIAMFinding

	// Get all cloud resources this role can access
	edges := g.GetOutEdges(role.ID)

	for _, e := range edges {
		if e.Type != graph.EdgeAllows {
			continue
		}

		resourceNode := g.GetNode(e.To)
		if resourceNode == nil {
			continue
		}

		resourceType := resourceNode.Metadata.ResourceType
		actions := e.Metadata.Actions

		// Check for secrets access
		if strings.Contains(resourceType, "secret") || strings.Contains(resourceType, "ssm") {
			if hasReadActions(actions) {
				findings = append(findings, CloudIAMFinding{
					Category:    CloudCategoryDataExposure,
					Severity:    graph.SeverityCritical,
					Title:       "Secrets Access",
					Description: "Role can read secrets from " + resourceType,
					Details: map[string]interface{}{
						"resource_type": resourceType,
						"resource_arn":  resourceNode.Metadata.ResourceARN,
						"actions":       actions,
					},
					Remediation: "Restrict secrets access to specific secret ARNs",
				})
			}
		}

		// Check for KMS access
		if strings.Contains(resourceType, "kms") {
			if hasAction(actions, "kms:Decrypt") || hasAction(actions, "kms:*") {
				findings = append(findings, CloudIAMFinding{
					Category:    CloudCategoryDataExposure,
					Severity:    graph.SeverityHigh,
					Title:       "KMS Decrypt Access",
					Description: "Role can decrypt data using KMS keys",
					Details: map[string]interface{}{
						"resource_type": resourceType,
						"resource_arn":  resourceNode.Metadata.ResourceARN,
					},
					Remediation: "Restrict KMS access to specific keys",
				})
			}
		}

		// Check for S3 bucket access
		if strings.Contains(resourceType, "s3") {
			if hasAction(actions, "s3:GetObject") || hasAction(actions, "s3:*") {
				findings = append(findings, CloudIAMFinding{
					Category:    CloudCategoryDataExposure,
					Severity:    graph.SeverityMedium,
					Title:       "S3 Bucket Read Access",
					Description: "Role can read objects from S3 buckets",
					Details: map[string]interface{}{
						"resource_type": resourceType,
						"resource_arn":  resourceNode.Metadata.ResourceARN,
					},
					Remediation: "Restrict S3 access to specific buckets and prefixes",
				})
			}
		}

		// Check for database access
		if strings.Contains(resourceType, "rds") || strings.Contains(resourceType, "dynamodb") {
			findings = append(findings, CloudIAMFinding{
				Category:    CloudCategoryDataExposure,
				Severity:    graph.SeverityHigh,
				Title:       "Database Access",
				Description: "Role has access to database resources",
				Details: map[string]interface{}{
					"resource_type": resourceType,
					"resource_arn":  resourceNode.Metadata.ResourceARN,
					"actions":       actions,
				},
				Remediation: "Review database access permissions",
			})
		}
	}

	return findings
}

// Helper functions

func hasIAMPrivEsc(actions []string) bool {
	privEscActions := []string{
		"iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
		"iam:AddUserToGroup", "iam:AttachUserPolicy", "iam:PutUserPolicy",
		"iam:AttachGroupPolicy", "iam:PutGroupPolicy",
		"iam:CreatePolicyVersion", "iam:SetDefaultPolicyVersion",
		"iam:UpdateAssumeRolePolicy", "iam:PassRole",
		"iam:CreateAccessKey", "iam:CreateLoginProfile",
		"iam:*",
	}

	for _, action := range actions {
		for _, privEsc := range privEscActions {
			if action == privEsc || action == "*" {
				return true
			}
		}
	}
	return false
}

func filterIAMActions(actions []string) []string {
	var iamActions []string
	for _, action := range actions {
		if strings.HasPrefix(action, "iam:") || action == "*" {
			iamActions = append(iamActions, action)
		}
	}
	return iamActions
}

func collectAllActions(role *graph.Node) map[string]bool {
	actions := make(map[string]bool)
	for _, policy := range role.Metadata.CloudPolicies {
		for _, stmt := range policy.Statements {
			for _, action := range stmt.Actions {
				actions[action] = true
			}
		}
	}
	return actions
}

func hasAllActions(allActions map[string]bool, required []string) bool {
	// If has wildcard, has everything
	if allActions["*"] {
		return true
	}

	for _, req := range required {
		if !hasActionMatch(allActions, req) {
			return false
		}
	}
	return true
}

func hasActionMatch(allActions map[string]bool, action string) bool {
	if allActions[action] {
		return true
	}

	// Check for service wildcard
	parts := strings.SplitN(action, ":", 2)
	if len(parts) == 2 {
		serviceWildcard := parts[0] + ":*"
		if allActions[serviceWildcard] {
			return true
		}
	}

	return false
}

func extractAccountFromARN(arn string) string {
	// ARN format: arn:partition:service:region:account-id:resource
	if !strings.HasPrefix(arn, "arn:") {
		return ""
	}

	parts := strings.Split(arn, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func hasHighRiskActions(actions []string) bool {
	highRisk := []string{
		"*", "iam:*", "s3:*", "ec2:*", "lambda:*",
		"sts:AssumeRole", "secretsmanager:GetSecretValue",
		"kms:Decrypt", "ssm:GetParameter",
	}

	for _, action := range actions {
		for _, hr := range highRisk {
			if action == hr {
				return true
			}
		}
	}
	return false
}

func isHighRiskService(service string) bool {
	highRisk := []string{
		"iam", "sts", "s3", "ec2", "lambda", "ecs", "eks",
		"secretsmanager", "ssm", "kms", "rds", "dynamodb",
		"cloudformation", "organizations", "sso",
	}

	for _, hr := range highRisk {
		if service == hr {
			return true
		}
	}
	return false
}

func hasReadActions(actions []string) bool {
	readPatterns := []string{"Get", "List", "Describe", "Read"}
	for _, action := range actions {
		for _, pattern := range readPatterns {
			if strings.Contains(action, pattern) || action == "*" {
				return true
			}
		}
	}
	return false
}

func hasAction(actions []string, target string) bool {
	for _, action := range actions {
		if action == target || action == "*" {
			return true
		}
	}
	return false
}

// TrustPolicyAnalysis analyzes IAM role trust policies
type TrustPolicyAnalysis struct {
	RoleARN          string
	TrustedEntities  []TrustedEntity
	IsPublic         bool
	AllowsAnyAccount bool
	Conditions       []TrustCondition
	Risks            []string
}

// TrustedEntity represents an entity that can assume the role
type TrustedEntity struct {
	Type      string // AWS, Service, Federated
	Principal string
	IsWide    bool
}

// TrustCondition represents a condition in the trust policy
type TrustCondition struct {
	Operator string
	Key      string
	Value    string
}

// AnalyzeTrustPolicy analyzes a role's trust policy for security issues
func AnalyzeTrustPolicy(roleARN string, trustDoc string) *TrustPolicyAnalysis {
	analysis := &TrustPolicyAnalysis{
		RoleARN: roleARN,
	}

	// Basic pattern matching for trust policy elements
	// In a real implementation, this would parse the JSON trust policy document

	// Check for * principal (public)
	if strings.Contains(trustDoc, `"Principal": "*"`) || strings.Contains(trustDoc, `"Principal":"*"`) {
		analysis.IsPublic = true
		analysis.Risks = append(analysis.Risks, "Trust policy allows any principal (public)")
	}

	// Check for AWS: * (any AWS account)
	if regexp.MustCompile(`"AWS"\s*:\s*"\*"`).MatchString(trustDoc) {
		analysis.AllowsAnyAccount = true
		analysis.Risks = append(analysis.Risks, "Trust policy allows any AWS account")
	}

	// Check for missing conditions on federated principals
	if strings.Contains(trustDoc, "Federated") && !strings.Contains(trustDoc, "Condition") {
		analysis.Risks = append(analysis.Risks, "Federated trust without conditions - any identity from the IdP can assume")
	}

	// Check for OIDC without audience/subject conditions
	if strings.Contains(trustDoc, "oidc") || strings.Contains(trustDoc, "token.actions.githubusercontent") {
		if !strings.Contains(trustDoc, "StringEquals") && !strings.Contains(trustDoc, "StringLike") {
			analysis.Risks = append(analysis.Risks, "OIDC trust without proper conditions")
		}
	}

	// Check for EKS OIDC (IRSA) specific issues
	if strings.Contains(trustDoc, "eks.amazonaws.com") || strings.Contains(trustDoc, "oidc.eks") {
		// Check if sub condition is present
		if !strings.Contains(trustDoc, ":sub") {
			analysis.Risks = append(analysis.Risks, "EKS IRSA trust without subject condition - any pod in cluster can assume")
		}
	}

	return analysis
}
