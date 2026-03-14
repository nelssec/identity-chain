package cloud

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestIsAzureAdminRole(t *testing.T) {
	tests := []struct {
		name     string
		roleName string
		want     bool
	}{
		{"Owner", "Owner", true},
		{"Contributor", "Contributor", true},
		{"User Access Administrator", "User Access Administrator", true},
		{"Global Administrator", "Global Administrator", true},
		{"Privileged Role Administrator", "Privileged Role Administrator", true},
		{"Reader", "Reader", false},
		{"Storage Blob Data Reader", "Storage Blob Data Reader", false},
		{"empty string", "", false},
		{"case sensitive - owner lowercase", "owner", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := isAzureAdminRole(tt.roleName)
			if got != tt.want {
				t.Errorf("isAzureAdminRole(%q) = %v, want %v", tt.roleName, got, tt.want)
			}
		})
	}
}

func TestClassifyAzureAction(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   string
	}{
		{"storage action", "Microsoft.Storage/storageAccounts/read", "storage-account"},
		{"keyvault action", "Microsoft.KeyVault/vaults/read", "key-vault"},
		{"sql action", "Microsoft.Sql/servers/databases/read", "sql-database"},
		{"compute action", "Microsoft.Compute/virtualMachines/read", "virtual-machine"},
		{"container service", "Microsoft.ContainerService/managedClusters/read", "aks-cluster"},
		{"web action", "Microsoft.Web/sites/read", "app-service"},
		{"service bus", "Microsoft.ServiceBus/namespaces/read", "service-bus"},
		{"event hub", "Microsoft.EventHub/namespaces/read", "event-hub"},
		{"cosmos db", "Microsoft.CosmosDB/databaseAccounts/read", "cosmos-db"},
		{"authorization", "Microsoft.Authorization/roleAssignments/read", "iam-resource"},
		{"unknown action", "Microsoft.Network/virtualNetworks/read", "azure-resource"},
		{"wildcard", "*", "azure-resource"},
		{"empty string", "", "azure-resource"},
		{"case insensitive", "MICROSOFT.STORAGE/storageAccounts/read", "storage-account"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAzureAction(tt.action)
			if got != tt.want {
				t.Errorf("classifyAzureAction(%q) = %q, want %q", tt.action, got, tt.want)
			}
		})
	}
}

func TestClassifyAzureActionSeverity(t *testing.T) {
	tests := []struct {
		name   string
		action string
		want   graph.Severity
	}{
		{"wildcard star", "*", graph.SeverityCritical},
		{"wildcard star-slash-star", "*/*", graph.SeverityCritical},
		{"authorization action", "Microsoft.Authorization/roleAssignments/write", graph.SeverityCritical},
		{"keyvault write", "Microsoft.KeyVault/vaults/secrets/write", graph.SeverityCritical},
		{"keyvault secrets read", "Microsoft.KeyVault/vaults/secrets/read", graph.SeverityCritical},
		{"storage write", "Microsoft.Storage/storageAccounts/write", graph.SeverityHigh},
		{"compute delete", "Microsoft.Compute/virtualMachines/delete", graph.SeverityHigh},
		{"action verb", "Microsoft.Compute/virtualMachines/start/action", graph.SeverityHigh},
		{"read action", "Microsoft.Storage/storageAccounts/read", graph.SeverityMedium},
		{"list action", "Microsoft.Resources/subscriptions/resourceGroups/read", graph.SeverityMedium},
		{"empty string", "", graph.SeverityMedium},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := classifyAzureActionSeverity(tt.action)
			if got != tt.want {
				t.Errorf("classifyAzureActionSeverity(%q) = %v, want %v", tt.action, got, tt.want)
			}
		})
	}
}

func TestDeduplicateResources(t *testing.T) {
	tests := []struct {
		name    string
		input   []ResourceAccess
		wantLen int
	}{
		{
			name:    "empty input",
			input:   []ResourceAccess{},
			wantLen: 0,
		},
		{
			name:    "nil input",
			input:   nil,
			wantLen: 0,
		},
		{
			name: "no duplicates",
			input: []ResourceAccess{
				{ResourceType: "storage-account", Actions: []string{"read"}, Severity: graph.SeverityMedium},
				{ResourceType: "key-vault", Actions: []string{"read"}, Severity: graph.SeverityMedium},
			},
			wantLen: 2,
		},
		{
			name: "duplicate resource types merged",
			input: []ResourceAccess{
				{ResourceType: "storage-account", Actions: []string{"read"}, Severity: graph.SeverityMedium},
				{ResourceType: "storage-account", Actions: []string{"write"}, Severity: graph.SeverityHigh},
			},
			wantLen: 1,
		},
		{
			name: "severity upgraded on merge",
			input: []ResourceAccess{
				{ResourceType: "storage-account", Actions: []string{"read"}, Severity: graph.SeverityMedium},
				{ResourceType: "storage-account", Actions: []string{"write"}, Severity: graph.SeverityCritical},
			},
			wantLen: 1,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := deduplicateResources(tt.input)
			if len(got) != tt.wantLen {
				t.Errorf("deduplicateResources() len = %d, want %d", len(got), tt.wantLen)
			}
		})
	}
}

func TestDeduplicateResourcesMergedActions(t *testing.T) {
	input := []ResourceAccess{
		{ResourceType: "storage-account", Actions: []string{"read"}, Severity: graph.SeverityMedium},
		{ResourceType: "storage-account", Actions: []string{"write"}, Severity: graph.SeverityHigh},
	}

	got := deduplicateResources(input)
	if len(got) != 1 {
		t.Fatalf("expected 1 resource, got %d", len(got))
	}
	if len(got[0].Actions) != 2 {
		t.Errorf("expected 2 merged actions, got %d: %v", len(got[0].Actions), got[0].Actions)
	}
	if got[0].Severity != graph.SeverityHigh {
		t.Errorf("expected severity %v, got %v", graph.SeverityHigh, got[0].Severity)
	}
}

func TestDeduplicateResourcesSeverityUpgrade(t *testing.T) {
	tests := []struct {
		name       string
		sev1       graph.Severity
		sev2       graph.Severity
		wantResult graph.Severity
	}{
		{"medium then critical upgrades", graph.SeverityMedium, graph.SeverityCritical, graph.SeverityCritical},
		{"medium then high upgrades", graph.SeverityMedium, graph.SeverityHigh, graph.SeverityHigh},
		{"high then critical upgrades", graph.SeverityHigh, graph.SeverityCritical, graph.SeverityCritical},
		{"critical then medium stays critical", graph.SeverityCritical, graph.SeverityMedium, graph.SeverityCritical},
		{"high then medium stays high", graph.SeverityHigh, graph.SeverityMedium, graph.SeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			input := []ResourceAccess{
				{ResourceType: "test", Actions: []string{"a"}, Severity: tt.sev1},
				{ResourceType: "test", Actions: []string{"b"}, Severity: tt.sev2},
			}
			got := deduplicateResources(input)
			if len(got) != 1 {
				t.Fatalf("expected 1, got %d", len(got))
			}
			if got[0].Severity != tt.wantResult {
				t.Errorf("severity = %v, want %v", got[0].Severity, tt.wantResult)
			}
		})
	}
}

func TestSafeStringValue(t *testing.T) {
	tests := []struct {
		name string
		s    *string
		want string
	}{
		{"nil pointer", nil, ""},
		{"non-nil pointer", strPtr("hello"), "hello"},
		{"empty string pointer", strPtr(""), ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := safeStringValue(tt.s)
			if got != tt.want {
				t.Errorf("safeStringValue() = %q, want %q", got, tt.want)
			}
		})
	}
}
