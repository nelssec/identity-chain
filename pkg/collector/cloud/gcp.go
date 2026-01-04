package cloud

import (
	"context"
	"fmt"
	"strings"

	"cloud.google.com/go/iam/admin/apiv1"
	"cloud.google.com/go/iam/admin/apiv1/adminpb"
	resourcemanager "cloud.google.com/go/resourcemanager/apiv3"
	"github.com/nelssec/identity-chain/pkg/graph"
	"google.golang.org/api/iterator"
	iampb "google.golang.org/genproto/googleapis/iam/v1"
)

type GCPCollector struct {
	iamClient      *admin.IamClient
	projectsClient *resourcemanager.ProjectsClient
	projectID      string
}

func NewGCPCollector(ctx context.Context, projectID string) (*GCPCollector, error) {
	iamClient, err := admin.NewIamClient(ctx)
	if err != nil {
		return nil, fmt.Errorf("failed to create IAM client: %w", err)
	}

	projectsClient, err := resourcemanager.NewProjectsClient(ctx)
	if err != nil {
		iamClient.Close()
		return nil, fmt.Errorf("failed to create projects client: %w", err)
	}

	return &GCPCollector{
		iamClient:      iamClient,
		projectsClient: projectsClient,
		projectID:      projectID,
	}, nil
}

func (g *GCPCollector) Close() {
	if g.iamClient != nil {
		g.iamClient.Close()
	}
	if g.projectsClient != nil {
		g.projectsClient.Close()
	}
}

func (g *GCPCollector) Provider() Provider {
	return ProviderGCP
}

func (g *GCPCollector) CollectRole(ctx context.Context, gcpSAEmail string) (*RoleInfo, error) {
	saName := extractGCPSAName(gcpSAEmail)
	projectID := extractGCPProject(gcpSAEmail)
	if projectID == "" {
		projectID = g.projectID
	}

	saResourceName := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, gcpSAEmail)

	sa, err := g.iamClient.GetServiceAccount(ctx, &adminpb.GetServiceAccountRequest{
		Name: saResourceName,
	})
	if err != nil {
		return nil, fmt.Errorf("failed to get service account %s: %w", gcpSAEmail, err)
	}

	roleInfo := &RoleInfo{
		Provider:  ProviderGCP,
		RoleARN:   gcpSAEmail,
		RoleName:  saName,
		AccountID: projectID,
		Policies:  make([]PolicyInfo, 0),
	}

	if sa.Description != "" {
		roleInfo.TrustPolicy = &TrustPolicy{
			TrustedEntities: []string{sa.Description},
		}
	}

	roles, err := g.GetRolesForServiceAccount(ctx, projectID, gcpSAEmail)
	if err == nil {
		for _, role := range roles {
			perms, _ := g.GetRolePermissions(ctx, role)
			roleInfo.Policies = append(roleInfo.Policies, PolicyInfo{
				Name:      role,
				Type:      "gcp-role",
				IsManaged: true,
				Statements: []Statement{{
					Effect:   "Allow",
					Action:   perms,
					Resource: []string{"*"},
				}},
			})
		}
	}

	return roleInfo, nil
}

func (g *GCPCollector) getProjectIAMBindings(ctx context.Context, projectID, saEmail string) ([]string, error) {
	return g.GetRolesForServiceAccount(ctx, projectID, saEmail)
}

func (g *GCPCollector) GetResourceAccess(ctx context.Context, role *RoleInfo) ([]ResourceAccess, error) {
	var resources []ResourceAccess

	for _, policy := range role.Policies {
		for _, stmt := range policy.Statements {
			if stmt.Effect != "Allow" {
				continue
			}

			for _, resource := range stmt.Resource {
				resourceType := classifyGCPResource(resource)
				resources = append(resources, ResourceAccess{
					ResourceType: resourceType,
					ResourceARN:  resource,
					Actions:      stmt.Action,
					Severity:     ClassifyCloudSeverity(stmt.Action, resourceType),
				})
			}
		}
	}

	return resources, nil
}

func (g *GCPCollector) GetRolesForServiceAccount(ctx context.Context, projectID, saEmail string) ([]string, error) {
	var roles []string

	projectName := fmt.Sprintf("projects/%s", projectID)

	req := &iampb.GetIamPolicyRequest{
		Resource: projectName,
	}

	policy, err := g.projectsClient.GetIamPolicy(ctx, req)
	if err != nil {
		return nil, fmt.Errorf("failed to get IAM policy: %w", err)
	}

	memberToMatch := fmt.Sprintf("serviceAccount:%s", saEmail)

	for _, binding := range policy.Bindings {
		for _, member := range binding.Members {
			if member == memberToMatch {
				roles = append(roles, binding.Role)
			}
		}
	}

	return roles, nil
}

func (g *GCPCollector) GetRolePermissions(ctx context.Context, roleName string) ([]string, error) {
	var permissions []string

	if strings.HasPrefix(roleName, "roles/") {
		req := &adminpb.GetRoleRequest{
			Name: roleName,
		}
		role, err := g.iamClient.GetRole(ctx, req)
		if err != nil {
			return nil, err
		}
		permissions = role.IncludedPermissions
	} else if strings.HasPrefix(roleName, "projects/") {
		req := &adminpb.GetRoleRequest{
			Name: roleName,
		}
		role, err := g.iamClient.GetRole(ctx, req)
		if err != nil {
			return nil, err
		}
		permissions = role.IncludedPermissions
	}

	return permissions, nil
}

func (g *GCPCollector) ListServiceAccountKeys(ctx context.Context, saEmail string) ([]*adminpb.ServiceAccountKey, error) {
	projectID := extractGCPProject(saEmail)
	if projectID == "" {
		projectID = g.projectID
	}

	saResourceName := fmt.Sprintf("projects/%s/serviceAccounts/%s", projectID, saEmail)

	req := &adminpb.ListServiceAccountKeysRequest{
		Name: saResourceName,
	}

	resp, err := g.iamClient.ListServiceAccountKeys(ctx, req)
	if err != nil {
		return nil, err
	}

	return resp.Keys, nil
}

func extractGCPSAName(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 0 {
		return parts[0]
	}
	return email
}

func extractGCPProject(email string) string {
	parts := strings.Split(email, "@")
	if len(parts) > 1 {
		domain := parts[1]
		if strings.HasSuffix(domain, ".iam.gserviceaccount.com") {
			return strings.TrimSuffix(domain, ".iam.gserviceaccount.com")
		}
	}
	return ""
}

func classifyGCPResource(resource string) string {
	if strings.Contains(resource, "storage.googleapis.com") || strings.HasPrefix(resource, "gs://") {
		return "gcs-bucket"
	}
	if strings.Contains(resource, "bigquery.googleapis.com") {
		return "bigquery-dataset"
	}
	if strings.Contains(resource, "secretmanager.googleapis.com") {
		return "secret-manager"
	}
	if strings.Contains(resource, "compute.googleapis.com") {
		return "compute-instance"
	}
	if strings.Contains(resource, "container.googleapis.com") {
		return "gke-cluster"
	}
	if strings.Contains(resource, "cloudfunctions.googleapis.com") {
		return "cloud-function"
	}
	if strings.Contains(resource, "run.googleapis.com") {
		return "cloud-run"
	}
	if strings.Contains(resource, "pubsub.googleapis.com") {
		return "pubsub-topic"
	}
	if strings.Contains(resource, "cloudsql.googleapis.com") {
		return "cloud-sql"
	}
	if strings.Contains(resource, "cloudkms.googleapis.com") {
		return "cloud-kms"
	}
	return "gcp-resource"
}

func ClassifyGCPPermissionSeverity(permissions []string) graph.Severity {
	for _, perm := range permissions {
		if strings.Contains(perm, ".admin") || strings.Contains(perm, ".setIamPolicy") {
			return graph.SeverityCritical
		}
		if strings.HasSuffix(perm, ".owner") || perm == "owner" {
			return graph.SeverityCritical
		}
		if strings.Contains(perm, "secretmanager.") && strings.Contains(perm, ".access") {
			return graph.SeverityCritical
		}
	}

	for _, perm := range permissions {
		if strings.Contains(perm, ".create") || strings.Contains(perm, ".delete") {
			return graph.SeverityHigh
		}
		if strings.Contains(perm, ".update") || strings.Contains(perm, ".write") {
			return graph.SeverityHigh
		}
		if strings.Contains(perm, "storage.objects.") {
			return graph.SeverityHigh
		}
	}

	return graph.SeverityMedium
}

type GCPWorkloadIdentityInfo struct {
	K8sNamespace       string
	K8sServiceAccount  string
	GCPServiceAccount  string
	GCPProject         string
	Roles              []string
	Permissions        []string
}

func (g *GCPCollector) AnalyzeWorkloadIdentity(ctx context.Context, k8sNS, k8sSA, gcpSA string) (*GCPWorkloadIdentityInfo, error) {
	projectID := extractGCPProject(gcpSA)
	if projectID == "" {
		projectID = g.projectID
	}

	info := &GCPWorkloadIdentityInfo{
		K8sNamespace:      k8sNS,
		K8sServiceAccount: k8sSA,
		GCPServiceAccount: gcpSA,
		GCPProject:        projectID,
	}

	roles, err := g.GetRolesForServiceAccount(ctx, projectID, gcpSA)
	if err == nil {
		info.Roles = roles

		for _, role := range roles {
			perms, err := g.GetRolePermissions(ctx, role)
			if err == nil {
				info.Permissions = append(info.Permissions, perms...)
			}
		}
	}

	return info, nil
}

func (g *GCPCollector) ListAllServiceAccounts(ctx context.Context, projectID string) ([]*adminpb.ServiceAccount, error) {
	var serviceAccounts []*adminpb.ServiceAccount

	req := &adminpb.ListServiceAccountsRequest{
		Name: fmt.Sprintf("projects/%s", projectID),
	}

	it := g.iamClient.ListServiceAccounts(ctx, req)
	for {
		sa, err := it.Next()
		if err == iterator.Done {
			break
		}
		if err != nil {
			return nil, err
		}
		serviceAccounts = append(serviceAccounts, sa)
	}

	return serviceAccounts, nil
}
