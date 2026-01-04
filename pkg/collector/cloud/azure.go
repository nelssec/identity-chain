package cloud

import (
	"context"
	"fmt"
	"strings"

	"github.com/Azure/azure-sdk-for-go/sdk/azidentity"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/authorization/armauthorization/v2"
	"github.com/Azure/azure-sdk-for-go/sdk/resourcemanager/msi/armmsi"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type AzureCollector struct {
	credential         *azidentity.DefaultAzureCredential
	subscriptionID     string
	roleAssignments    *armauthorization.RoleAssignmentsClient
	roleDefinitions    *armauthorization.RoleDefinitionsClient
	managedIdentities  *armmsi.UserAssignedIdentitiesClient
}

func NewAzureCollector(ctx context.Context, subscriptionID string) (*AzureCollector, error) {
	cred, err := azidentity.NewDefaultAzureCredential(nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create Azure credentials: %w", err)
	}

	roleAssignmentsClient, err := armauthorization.NewRoleAssignmentsClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role assignments client: %w", err)
	}

	roleDefsClient, err := armauthorization.NewRoleDefinitionsClient(cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create role definitions client: %w", err)
	}

	msiClient, err := armmsi.NewUserAssignedIdentitiesClient(subscriptionID, cred, nil)
	if err != nil {
		return nil, fmt.Errorf("failed to create managed identities client: %w", err)
	}

	return &AzureCollector{
		credential:        cred,
		subscriptionID:    subscriptionID,
		roleAssignments:   roleAssignmentsClient,
		roleDefinitions:   roleDefsClient,
		managedIdentities: msiClient,
	}, nil
}

func (a *AzureCollector) Provider() Provider {
	return ProviderAzure
}

func (a *AzureCollector) CollectRole(ctx context.Context, clientID string) (*RoleInfo, error) {
	identity, err := a.findManagedIdentity(ctx, clientID)
	if err != nil {
		return nil, fmt.Errorf("failed to find managed identity: %w", err)
	}

	roleInfo := &RoleInfo{
		Provider:  ProviderAzure,
		RoleARN:   clientID,
		RoleName:  safeStringValue(identity.Name),
		AccountID: a.subscriptionID,
		Policies:  make([]PolicyInfo, 0),
	}

	principalID := ""
	if identity.Properties != nil && identity.Properties.PrincipalID != nil {
		principalID = *identity.Properties.PrincipalID
	}

	if principalID != "" {
		assignments, err := a.getRoleAssignments(ctx, principalID)
		if err == nil {
			for _, assignment := range assignments {
				roleDefID := ""
				if assignment.Properties != nil && assignment.Properties.RoleDefinitionID != nil {
					roleDefID = *assignment.Properties.RoleDefinitionID
				}

				if roleDefID != "" {
					roleDef, err := a.getRoleDefinition(ctx, roleDefID)
					if err == nil {
						policy := a.roleDefinitionToPolicy(roleDef)
						roleInfo.Policies = append(roleInfo.Policies, policy)
					}
				}
			}
		}
	}

	return roleInfo, nil
}

func (a *AzureCollector) findManagedIdentity(ctx context.Context, clientID string) (*armmsi.Identity, error) {
	pager := a.managedIdentities.NewListBySubscriptionPager(nil)

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}

		for _, identity := range page.Value {
			if identity.Properties != nil && identity.Properties.ClientID != nil {
				if *identity.Properties.ClientID == clientID {
					return identity, nil
				}
			}
		}
	}

	return nil, fmt.Errorf("managed identity not found: %s", clientID)
}

func (a *AzureCollector) getRoleAssignments(ctx context.Context, principalID string) ([]*armauthorization.RoleAssignment, error) {
	var assignments []*armauthorization.RoleAssignment

	filter := fmt.Sprintf("principalId eq '%s'", principalID)
	pager := a.roleAssignments.NewListForSubscriptionPager(&armauthorization.RoleAssignmentsClientListForSubscriptionOptions{
		Filter: &filter,
	})

	for pager.More() {
		page, err := pager.NextPage(ctx)
		if err != nil {
			return nil, err
		}
		assignments = append(assignments, page.Value...)
	}

	return assignments, nil
}

func (a *AzureCollector) getRoleDefinition(ctx context.Context, roleDefID string) (*armauthorization.RoleDefinition, error) {
	scope := fmt.Sprintf("/subscriptions/%s", a.subscriptionID)

	resp, err := a.roleDefinitions.GetByID(ctx, roleDefID, nil)
	if err != nil {
		pager := a.roleDefinitions.NewListPager(scope, nil)
		for pager.More() {
			page, err := pager.NextPage(ctx)
			if err != nil {
				return nil, err
			}
			for _, def := range page.Value {
				if def.ID != nil && *def.ID == roleDefID {
					return def, nil
				}
			}
		}
		return nil, fmt.Errorf("role definition not found: %s", roleDefID)
	}

	return &resp.RoleDefinition, nil
}

func (a *AzureCollector) roleDefinitionToPolicy(roleDef *armauthorization.RoleDefinition) PolicyInfo {
	policy := PolicyInfo{
		Type:       "azure-rbac",
		IsManaged:  true,
		Statements: make([]Statement, 0),
	}

	if roleDef.Properties != nil {
		if roleDef.Properties.RoleName != nil {
			policy.Name = *roleDef.Properties.RoleName
		}

		for _, perm := range roleDef.Properties.Permissions {
			if perm.Actions != nil {
				var actions []string
				for _, action := range perm.Actions {
					if action != nil {
						actions = append(actions, *action)
					}
				}
				policy.Statements = append(policy.Statements, Statement{
					Effect:   "Allow",
					Action:   actions,
					Resource: []string{"*"},
				})
			}

			if perm.DataActions != nil {
				var dataActions []string
				for _, action := range perm.DataActions {
					if action != nil {
						dataActions = append(dataActions, *action)
					}
				}
				if len(dataActions) > 0 {
					policy.Statements = append(policy.Statements, Statement{
						Effect:   "Allow",
						Action:   dataActions,
						Resource: []string{"*"},
					})
				}
			}
		}

		policy.IsAdmin = isAzureAdminRole(policy.Name)
	}

	return policy
}

func (a *AzureCollector) GetResourceAccess(ctx context.Context, role *RoleInfo) ([]ResourceAccess, error) {
	var resources []ResourceAccess

	for _, policy := range role.Policies {
		for _, stmt := range policy.Statements {
			if stmt.Effect != "Allow" {
				continue
			}

			for _, action := range stmt.Action {
				resourceType := classifyAzureAction(action)
				resources = append(resources, ResourceAccess{
					ResourceType: resourceType,
					ResourceARN:  action,
					Actions:      []string{action},
					Severity:     classifyAzureActionSeverity(action),
				})
			}
		}
	}

	resources = deduplicateResources(resources)
	return resources, nil
}

func isAzureAdminRole(roleName string) bool {
	adminRoles := []string{
		"Owner",
		"Contributor",
		"User Access Administrator",
		"Global Administrator",
		"Privileged Role Administrator",
	}
	for _, admin := range adminRoles {
		if roleName == admin {
			return true
		}
	}
	return false
}

func classifyAzureAction(action string) string {
	action = strings.ToLower(action)

	if strings.Contains(action, "microsoft.storage") {
		return "storage-account"
	}
	if strings.Contains(action, "microsoft.keyvault") {
		return "key-vault"
	}
	if strings.Contains(action, "microsoft.sql") {
		return "sql-database"
	}
	if strings.Contains(action, "microsoft.compute") {
		return "virtual-machine"
	}
	if strings.Contains(action, "microsoft.containerservice") {
		return "aks-cluster"
	}
	if strings.Contains(action, "microsoft.web") {
		return "app-service"
	}
	if strings.Contains(action, "microsoft.servicebus") {
		return "service-bus"
	}
	if strings.Contains(action, "microsoft.eventhub") {
		return "event-hub"
	}
	if strings.Contains(action, "microsoft.cosmosdb") {
		return "cosmos-db"
	}
	if strings.Contains(action, "microsoft.authorization") {
		return "iam-resource"
	}
	return "azure-resource"
}

func classifyAzureActionSeverity(action string) graph.Severity {
	action = strings.ToLower(action)

	if action == "*" || action == "*/*" {
		return graph.SeverityCritical
	}

	if strings.Contains(action, "microsoft.authorization") {
		return graph.SeverityCritical
	}
	if strings.Contains(action, "/write") && strings.Contains(action, "microsoft.keyvault") {
		return graph.SeverityCritical
	}
	if strings.Contains(action, "secrets") && strings.Contains(action, "keyvault") {
		return graph.SeverityCritical
	}

	if strings.Contains(action, "/write") || strings.Contains(action, "/delete") {
		return graph.SeverityHigh
	}
	if strings.Contains(action, "/action") {
		return graph.SeverityHigh
	}

	return graph.SeverityMedium
}

func deduplicateResources(resources []ResourceAccess) []ResourceAccess {
	seen := make(map[string]int)
	var result []ResourceAccess

	for _, res := range resources {
		key := res.ResourceType
		if idx, exists := seen[key]; exists {
			result[idx].Actions = mergeActions(result[idx].Actions, res.Actions)
			if res.Severity == graph.SeverityCritical ||
				(res.Severity == graph.SeverityHigh && result[idx].Severity != graph.SeverityCritical) {
				result[idx].Severity = res.Severity
			}
		} else {
			seen[key] = len(result)
			result = append(result, res)
		}
	}

	return result
}

func safeStringValue(s *string) string {
	if s == nil {
		return ""
	}
	return *s
}

type AzureWorkloadIdentityInfo struct {
	K8sNamespace       string
	K8sServiceAccount  string
	ManagedIdentityID  string
	ClientID           string
	TenantID           string
	SubscriptionID     string
	RoleAssignments    []AzureRoleAssignment
}

type AzureRoleAssignment struct {
	RoleName   string
	Scope      string
	Actions    []string
	DataActions []string
}

func (a *AzureCollector) AnalyzeWorkloadIdentity(ctx context.Context, clientID string) (*AzureWorkloadIdentityInfo, error) {
	identity, err := a.findManagedIdentity(ctx, clientID)
	if err != nil {
		return nil, err
	}

	info := &AzureWorkloadIdentityInfo{
		ClientID:       clientID,
		SubscriptionID: a.subscriptionID,
	}

	if identity.Properties != nil {
		if identity.Properties.TenantID != nil {
			info.TenantID = *identity.Properties.TenantID
		}
		if identity.ID != nil {
			info.ManagedIdentityID = *identity.ID
		}

		if identity.Properties.PrincipalID != nil {
			assignments, err := a.getRoleAssignments(ctx, *identity.Properties.PrincipalID)
			if err == nil {
				for _, assignment := range assignments {
					if assignment.Properties == nil || assignment.Properties.RoleDefinitionID == nil {
						continue
					}

					roleDef, err := a.getRoleDefinition(ctx, *assignment.Properties.RoleDefinitionID)
					if err != nil {
						continue
					}

					ra := AzureRoleAssignment{}
					if roleDef.Properties != nil && roleDef.Properties.RoleName != nil {
						ra.RoleName = *roleDef.Properties.RoleName
					}
					if assignment.Properties.Scope != nil {
						ra.Scope = *assignment.Properties.Scope
					}

					if roleDef.Properties != nil {
						for _, perm := range roleDef.Properties.Permissions {
							if perm.Actions != nil {
								for _, action := range perm.Actions {
									if action != nil {
										ra.Actions = append(ra.Actions, *action)
									}
								}
							}
							if perm.DataActions != nil {
								for _, action := range perm.DataActions {
									if action != nil {
										ra.DataActions = append(ra.DataActions, *action)
									}
								}
							}
						}
					}

					info.RoleAssignments = append(info.RoleAssignments, ra)
				}
			}
		}
	}

	return info, nil
}
