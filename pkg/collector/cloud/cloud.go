package cloud

import (
	"context"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type Provider string

const (
	ProviderAWS   Provider = "aws"
	ProviderGCP   Provider = "gcp"
	ProviderAzure Provider = "azure"
)

type RoleInfo struct {
	Provider    Provider
	RoleARN     string
	RoleName    string
	AccountID   string
	Policies    []PolicyInfo
	TrustPolicy *TrustPolicy
}

type PolicyInfo struct {
	Name       string
	ARN        string
	Type       string
	Document   *PolicyDocument
	IsManaged  bool
	IsAdmin    bool
	Statements []Statement
}

type PolicyDocument struct {
	Version   string
	Statement []Statement
}

type Statement struct {
	Sid       string
	Effect    string
	Action    []string
	Resource  []string
	Condition map[string]interface{}
}

type TrustPolicy struct {
	TrustedEntities []string
	Conditions      map[string]string
}

type ResourceAccess struct {
	ResourceType string
	ResourceARN  string
	Actions      []string
	Severity     graph.Severity
}

type Collector interface {
	Provider() Provider
	CollectRole(ctx context.Context, roleARN string) (*RoleInfo, error)
	GetResourceAccess(ctx context.Context, role *RoleInfo) ([]ResourceAccess, error)
}

type MultiCloudCollector struct {
	collectors map[Provider]Collector
}

func NewMultiCloudCollector() *MultiCloudCollector {
	return &MultiCloudCollector{
		collectors: make(map[Provider]Collector),
	}
}

func (m *MultiCloudCollector) Register(c Collector) {
	m.collectors[c.Provider()] = c
}

func (m *MultiCloudCollector) GetCollector(p Provider) Collector {
	return m.collectors[p]
}

func (m *MultiCloudCollector) CollectForServiceAccount(ctx context.Context, builder *graph.Builder, saNode *graph.Node) error {
	var provider Provider
	var roleARN string

	if saNode.Metadata.CloudRoleARN != "" {
		roleARN = saNode.Metadata.CloudRoleARN
		if len(roleARN) > 4 && roleARN[:4] == "arn:" {
			provider = ProviderAWS
		} else if saNode.Metadata.CloudProvider != "" {
			provider = Provider(saNode.Metadata.CloudProvider)
		}
	} else if saNode.Metadata.GCPServiceAccount != "" {
		provider = ProviderGCP
		roleARN = saNode.Metadata.GCPServiceAccount
	} else if saNode.Metadata.AzureManagedID != "" {
		provider = ProviderAzure
		roleARN = saNode.Metadata.AzureManagedID
	}

	if provider == "" || roleARN == "" {
		return nil
	}
	collector := m.collectors[provider]
	if collector == nil {
		return nil
	}

	roleInfo, err := collector.CollectRole(ctx, roleARN)
	if err != nil {
		return err
	}

	var graphPolicies []graph.CloudPolicy
	for _, pi := range roleInfo.Policies {
		gp := graph.CloudPolicy{
			Name:    pi.Name,
			ARN:     pi.ARN,
			Type:    pi.Type,
			IsAdmin: pi.IsAdmin,
		}
		for _, stmt := range pi.Statements {
			if stmt.Effect == "Allow" {
				gp.Statements = append(gp.Statements, graph.PolicyStatement{
					Effect:    stmt.Effect,
					Actions:   stmt.Action,
					Resources: stmt.Resource,
				})
			}
		}
		graphPolicies = append(graphPolicies, gp)
	}

	cloudRoleID := graph.GenerateNodeID(graph.NodeCloudRole, "", roleARN)

	if existingNode := builder.Graph().GetNode(cloudRoleID); existingNode != nil {
		existingNode.Metadata.CloudPolicies = graphPolicies
		existingNode.Metadata.CloudRoleARN = roleARN
		for _, p := range graphPolicies {
			if p.ARN != "" {
				existingNode.Metadata.PolicyARNs = append(existingNode.Metadata.PolicyARNs, p.ARN)
			} else {
				existingNode.Metadata.PolicyARNs = append(existingNode.Metadata.PolicyARNs, p.Name)
			}
		}
	} else {
		builder.AddCloudRoleWithPolicies(cloudRoleID, roleInfo.RoleName, roleARN, string(provider), graphPolicies)
		builder.AddCloudAssumeEdge(saNode.ID, cloudRoleID)
	}

	resources, err := collector.GetResourceAccess(ctx, roleInfo)
	if err != nil {
		return err
	}

	for _, res := range resources {
		resourceID := graph.GenerateNodeID(graph.NodeCloudResource, string(provider), res.ResourceARN)
		builder.AddCloudResource(resourceID, res.ResourceType, res.ResourceARN, string(provider))
		builder.AddCloudAllowEdge(cloudRoleID, resourceID, res.Actions, res.Severity)
	}

	return nil
}

func DetectProvider(annotations map[string]string) (Provider, string) {
	if arn, ok := annotations["eks.amazonaws.com/role-arn"]; ok {
		return ProviderAWS, arn
	}
	if sa, ok := annotations["iam.gke.io/gcp-service-account"]; ok {
		return ProviderGCP, sa
	}
	if clientID, ok := annotations["azure.workload.identity/client-id"]; ok {
		return ProviderAzure, clientID
	}
	return "", ""
}

func ClassifyCloudSeverity(actions []string, resourceType string) graph.Severity {
	for _, action := range actions {
		if action == "*" || action == "*:*" {
			return graph.SeverityCritical
		}
		if isAdminAction(action) {
			return graph.SeverityCritical
		}
		if isHighRiskAction(action) {
			return graph.SeverityHigh
		}
	}

	if isHighRiskResource(resourceType) {
		return graph.SeverityHigh
	}

	return graph.SeverityMedium
}

func isAdminAction(action string) bool {
	adminPatterns := []string{
		"iam:*", "iam:CreateRole", "iam:AttachRolePolicy", "iam:PutRolePolicy",
		"sts:AssumeRole", "sts:*",
		"secretsmanager:*", "ssm:GetParameter", "ssm:GetParameters",
		"kms:*", "kms:Decrypt",
		"ec2:*", "lambda:*", "ecs:*",
		"s3:*",
		"roles/owner", "roles/editor", "roles/iam.admin",
	}
	for _, pattern := range adminPatterns {
		if matchAction(action, pattern) {
			return true
		}
	}
	return false
}

func isHighRiskAction(action string) bool {
	highRiskPatterns := []string{
		"s3:GetObject", "s3:PutObject", "s3:DeleteObject",
		"secretsmanager:GetSecretValue",
		"ssm:GetParameter", "ssm:GetParametersByPath",
		"dynamodb:*", "rds:*",
		"ec2:RunInstances", "ec2:TerminateInstances",
		"lambda:InvokeFunction", "lambda:UpdateFunctionCode",
		"storage.objects.get", "storage.objects.create",
		"bigquery.tables.getData",
	}
	for _, pattern := range highRiskPatterns {
		if matchAction(action, pattern) {
			return true
		}
	}
	return false
}

func isHighRiskResource(resourceType string) bool {
	highRisk := []string{
		"s3", "bucket", "secret", "ssm", "kms", "key",
		"database", "rds", "dynamodb",
		"storage", "bigquery",
	}
	for _, hr := range highRisk {
		if contains(resourceType, hr) {
			return true
		}
	}
	return false
}

func matchAction(action, pattern string) bool {
	if action == pattern {
		return true
	}
	if len(pattern) > 0 && pattern[len(pattern)-1] == '*' {
		prefix := pattern[:len(pattern)-1]
		return len(action) >= len(prefix) && action[:len(prefix)] == prefix
	}
	return false
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > len(substr) && containsSubstr(s, substr))
}

func containsSubstr(s, substr string) bool {
	for i := 0; i <= len(s)-len(substr); i++ {
		if s[i:i+len(substr)] == substr {
			return true
		}
	}
	return false
}
