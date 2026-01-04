package cloud

import (
	"context"
	"encoding/json"
	"fmt"
	"net/url"
	"strings"

	"github.com/aws/aws-sdk-go-v2/aws"
	"github.com/aws/aws-sdk-go-v2/config"
	"github.com/aws/aws-sdk-go-v2/service/iam"
	"github.com/aws/aws-sdk-go-v2/service/iam/types"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type AWSCollector struct {
	client *iam.Client
	region string
}

func NewAWSCollector(ctx context.Context, region string) (*AWSCollector, error) {
	var opts []func(*config.LoadOptions) error
	if region != "" {
		opts = append(opts, config.WithRegion(region))
	}

	cfg, err := config.LoadDefaultConfig(ctx, opts...)
	if err != nil {
		return nil, fmt.Errorf("failed to load AWS config: %w", err)
	}

	return &AWSCollector{
		client: iam.NewFromConfig(cfg),
		region: cfg.Region,
	}, nil
}

func (a *AWSCollector) Provider() Provider {
	return ProviderAWS
}

func (a *AWSCollector) CollectRole(ctx context.Context, roleARN string) (*RoleInfo, error) {
	roleName := extractRoleName(roleARN)
	accountID := extractAccountID(roleARN)

	roleOutput, err := a.client.GetRole(ctx, &iam.GetRoleInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get role %s: %w", roleName, err)
	}

	roleInfo := &RoleInfo{
		Provider:  ProviderAWS,
		RoleARN:   roleARN,
		RoleName:  roleName,
		AccountID: accountID,
		Policies:  make([]PolicyInfo, 0),
	}

	if roleOutput.Role.AssumeRolePolicyDocument != nil {
		trustDoc, _ := url.QueryUnescape(*roleOutput.Role.AssumeRolePolicyDocument)
		roleInfo.TrustPolicy = parseTrustPolicy(trustDoc)
	}

	inlinePolicies, err := a.getInlinePolicies(ctx, roleName)
	if err == nil {
		roleInfo.Policies = append(roleInfo.Policies, inlinePolicies...)
	}

	attachedPolicies, err := a.getAttachedPolicies(ctx, roleName)
	if err == nil {
		roleInfo.Policies = append(roleInfo.Policies, attachedPolicies...)
	}

	return roleInfo, nil
}

func (a *AWSCollector) getInlinePolicies(ctx context.Context, roleName string) ([]PolicyInfo, error) {
	var policies []PolicyInfo

	listOutput, err := a.client.ListRolePolicies(ctx, &iam.ListRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, err
	}

	for _, policyName := range listOutput.PolicyNames {
		policyOutput, err := a.client.GetRolePolicy(ctx, &iam.GetRolePolicyInput{
			RoleName:   aws.String(roleName),
			PolicyName: aws.String(policyName),
		})
		if err != nil {
			continue
		}

		policyDoc, _ := url.QueryUnescape(*policyOutput.PolicyDocument)
		doc := parsePolicyDocument(policyDoc)

		policies = append(policies, PolicyInfo{
			Name:       policyName,
			Type:       "inline",
			IsManaged:  false,
			Document:   doc,
			Statements: doc.Statement,
			IsAdmin:    isAdminPolicy(doc),
		})
	}

	return policies, nil
}

func (a *AWSCollector) getAttachedPolicies(ctx context.Context, roleName string) ([]PolicyInfo, error) {
	var policies []PolicyInfo

	listOutput, err := a.client.ListAttachedRolePolicies(ctx, &iam.ListAttachedRolePoliciesInput{
		RoleName: aws.String(roleName),
	})
	if err != nil {
		return nil, err
	}

	for _, attached := range listOutput.AttachedPolicies {
		policyOutput, err := a.client.GetPolicy(ctx, &iam.GetPolicyInput{
			PolicyArn: attached.PolicyArn,
		})
		if err != nil {
			continue
		}

		versionOutput, err := a.client.GetPolicyVersion(ctx, &iam.GetPolicyVersionInput{
			PolicyArn: attached.PolicyArn,
			VersionId: policyOutput.Policy.DefaultVersionId,
		})
		if err != nil {
			continue
		}

		policyDoc, _ := url.QueryUnescape(*versionOutput.PolicyVersion.Document)
		doc := parsePolicyDocument(policyDoc)

		policies = append(policies, PolicyInfo{
			Name:       *attached.PolicyName,
			ARN:        *attached.PolicyArn,
			Type:       "managed",
			IsManaged:  true,
			Document:   doc,
			Statements: doc.Statement,
			IsAdmin:    isAdminPolicy(doc) || isAWSManagedAdmin(*attached.PolicyArn),
		})
	}

	return policies, nil
}

func (a *AWSCollector) GetResourceAccess(ctx context.Context, role *RoleInfo) ([]ResourceAccess, error) {
	resourceMap := make(map[string]*ResourceAccess)

	for _, policy := range role.Policies {
		for _, stmt := range policy.Statements {
			if stmt.Effect != "Allow" {
				continue
			}

			for _, resource := range stmt.Resource {
				resourceType := classifyAWSResource(resource)
				key := resourceType + ":" + resource

				if existing, ok := resourceMap[key]; ok {
					existing.Actions = mergeActions(existing.Actions, stmt.Action)
				} else {
					resourceMap[key] = &ResourceAccess{
						ResourceType: resourceType,
						ResourceARN:  resource,
						Actions:      stmt.Action,
						Severity:     ClassifyCloudSeverity(stmt.Action, resourceType),
					}
				}
			}
		}
	}

	result := make([]ResourceAccess, 0, len(resourceMap))
	for _, access := range resourceMap {
		result = append(result, *access)
	}

	return result, nil
}

func extractRoleName(roleARN string) string {
	parts := strings.Split(roleARN, "/")
	if len(parts) > 1 {
		return parts[len(parts)-1]
	}
	parts = strings.Split(roleARN, ":")
	if len(parts) > 0 {
		return parts[len(parts)-1]
	}
	return roleARN
}

func extractAccountID(roleARN string) string {
	parts := strings.Split(roleARN, ":")
	if len(parts) >= 5 {
		return parts[4]
	}
	return ""
}

func parseTrustPolicy(doc string) *TrustPolicy {
	var policyDoc struct {
		Statement []struct {
			Principal map[string]interface{} `json:"Principal"`
			Condition map[string]interface{} `json:"Condition"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(doc), &policyDoc); err != nil {
		return nil
	}

	trust := &TrustPolicy{
		TrustedEntities: make([]string, 0),
		Conditions:      make(map[string]string),
	}

	for _, stmt := range policyDoc.Statement {
		for key, val := range stmt.Principal {
			switch v := val.(type) {
			case string:
				trust.TrustedEntities = append(trust.TrustedEntities, key+":"+v)
			case []interface{}:
				for _, item := range v {
					if s, ok := item.(string); ok {
						trust.TrustedEntities = append(trust.TrustedEntities, key+":"+s)
					}
				}
			}
		}
	}

	return trust
}

func parsePolicyDocument(doc string) *PolicyDocument {
	var rawDoc struct {
		Version   string `json:"Version"`
		Statement []struct {
			Sid       string      `json:"Sid"`
			Effect    string      `json:"Effect"`
			Action    interface{} `json:"Action"`
			Resource  interface{} `json:"Resource"`
			Condition interface{} `json:"Condition"`
		} `json:"Statement"`
	}

	if err := json.Unmarshal([]byte(doc), &rawDoc); err != nil {
		return &PolicyDocument{}
	}

	policyDoc := &PolicyDocument{
		Version:   rawDoc.Version,
		Statement: make([]Statement, 0, len(rawDoc.Statement)),
	}

	for _, stmt := range rawDoc.Statement {
		s := Statement{
			Sid:      stmt.Sid,
			Effect:   stmt.Effect,
			Action:   toStringSlice(stmt.Action),
			Resource: toStringSlice(stmt.Resource),
		}
		policyDoc.Statement = append(policyDoc.Statement, s)
	}

	return policyDoc
}

func toStringSlice(v interface{}) []string {
	switch val := v.(type) {
	case string:
		return []string{val}
	case []interface{}:
		result := make([]string, 0, len(val))
		for _, item := range val {
			if s, ok := item.(string); ok {
				result = append(result, s)
			}
		}
		return result
	}
	return nil
}

func isAdminPolicy(doc *PolicyDocument) bool {
	for _, stmt := range doc.Statement {
		if stmt.Effect != "Allow" {
			continue
		}
		for _, action := range stmt.Action {
			if action == "*" {
				for _, resource := range stmt.Resource {
					if resource == "*" {
						return true
					}
				}
			}
		}
	}
	return false
}

func isAWSManagedAdmin(policyARN string) bool {
	adminPolicies := []string{
		"arn:aws:iam::aws:policy/AdministratorAccess",
		"arn:aws:iam::aws:policy/PowerUserAccess",
		"arn:aws:iam::aws:policy/IAMFullAccess",
	}
	for _, admin := range adminPolicies {
		if policyARN == admin {
			return true
		}
	}
	return false
}

func classifyAWSResource(resourceARN string) string {
	if resourceARN == "*" {
		return "all-resources"
	}

	arnParts := strings.Split(resourceARN, ":")
	if len(arnParts) < 3 {
		return "unknown"
	}

	service := arnParts[2]
	switch service {
	case "s3":
		return "s3-bucket"
	case "secretsmanager":
		return "secrets-manager"
	case "ssm":
		return "ssm-parameter"
	case "kms":
		return "kms-key"
	case "dynamodb":
		return "dynamodb-table"
	case "rds":
		return "rds-database"
	case "ec2":
		return "ec2-instance"
	case "lambda":
		return "lambda-function"
	case "ecs":
		return "ecs-service"
	case "eks":
		return "eks-cluster"
	case "sqs":
		return "sqs-queue"
	case "sns":
		return "sns-topic"
	case "iam":
		return "iam-resource"
	case "sts":
		return "sts-resource"
	default:
		return service
	}
}

func mergeActions(existing, new []string) []string {
	seen := make(map[string]bool)
	for _, a := range existing {
		seen[a] = true
	}
	for _, a := range new {
		if !seen[a] {
			existing = append(existing, a)
			seen[a] = true
		}
	}
	return existing
}

type AWSSimulator struct {
	client *iam.Client
}

func NewAWSSimulator(client *iam.Client) *AWSSimulator {
	return &AWSSimulator{client: client}
}

func (s *AWSSimulator) SimulateActions(ctx context.Context, roleARN string, actions []string, resources []string) ([]SimulationResult, error) {
	var results []SimulationResult

	input := &iam.SimulatePrincipalPolicyInput{
		PolicySourceArn: aws.String(roleARN),
		ActionNames:     actions,
		ResourceArns:    resources,
	}

	output, err := s.client.SimulatePrincipalPolicy(ctx, input)
	if err != nil {
		return nil, fmt.Errorf("policy simulation failed: %w", err)
	}

	for _, result := range output.EvaluationResults {
		results = append(results, SimulationResult{
			Action:   *result.EvalActionName,
			Resource: safeString(result.EvalResourceName),
			Decision: string(result.EvalDecision),
			Allowed:  result.EvalDecision == types.PolicyEvaluationDecisionTypeAllowed,
		})
	}

	return results, nil
}

type SimulationResult struct {
	Action   string
	Resource string
	Decision string
	Allowed  bool
}

func safeString(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

func ClassifyAWSSeverity(actions []string, resourceType string) graph.Severity {
	return ClassifyCloudSeverity(actions, resourceType)
}
