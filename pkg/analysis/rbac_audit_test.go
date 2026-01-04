package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestRunRBACAudit_EmptyCluster(t *testing.T) {
	g := graph.New()

	opts := RBACAuditOptions{
		IncludeSystem: false,
	}

	result := RunRBACAudit(g, opts)

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if result.TotalFindings != 0 {
		t.Errorf("expected 0 findings for empty cluster, got %d", result.TotalFindings)
	}
}

func TestRunRBACAudit_WildcardCheck(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "admin-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "admin-sa",
		Namespace: "prod",
	})

	roleID := graph.GenerateNodeID(graph.NodeRole, "prod", "wildcard-role")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "wildcard-role",
		Namespace: "prod",
	})

	bindEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindEdge)

	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "", "*")
	g.AddNode(&graph.Node{
		ID:   resourceID,
		Type: graph.NodeK8sResource,
		Name: "*",
		Metadata: graph.NodeMetadata{
			ResourceKind: "*",
		},
	})

	grantEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantEdge.Metadata.Verbs = []string{"*"}
	g.AddEdge(grantEdge)

	opts := RBACAuditOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"RBAC003"},
	}

	result := RunRBACAudit(g, opts)

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	foundWildcard := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC003" {
			foundWildcard = true
			break
		}
	}

	if !foundWildcard {
		t.Error("expected to find wildcard finding (RBAC003)")
	}
}

func TestRunRBACAudit_SecretsAccessCheck(t *testing.T) {
	g := graph.New()

	workloadID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "app")
	g.AddNode(&graph.Node{
		ID:        workloadID,
		Type:      graph.NodeWorkload,
		Name:      "app",
		Namespace: "prod",
	})

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "app-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "app-sa",
		Namespace: "prod",
	})

	g.AddEdge(graph.NewEdge(graph.EdgeUses, workloadID, saID))

	roleID := graph.GenerateNodeID(graph.NodeRole, "prod", "secret-reader")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "secret-reader",
		Namespace: "prod",
	})

	bindEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindEdge)

	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "", "secrets")
	g.AddNode(&graph.Node{
		ID:   resourceID,
		Type: graph.NodeK8sResource,
		Name: "secrets",
		Metadata: graph.NodeMetadata{
			ResourceKind: "secrets",
		},
	})

	grantEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantEdge.Metadata.Verbs = []string{"get", "list"}
	g.AddEdge(grantEdge)

	opts := RBACAuditOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"RBAC005"},
	}

	result := RunRBACAudit(g, opts)

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	foundSecrets := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC005" {
			foundSecrets = true
			break
		}
	}

	if !foundSecrets {
		t.Error("expected to find secrets access finding (RBAC005)")
	}
}

func TestRunRBACAudit_SkipChecks(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "app-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "app-sa",
		Namespace: "prod",
	})

	roleID := graph.GenerateNodeID(graph.NodeRole, "prod", "wildcard-role")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "wildcard-role",
		Namespace: "prod",
	})

	bindEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindEdge)

	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "", "*")
	g.AddNode(&graph.Node{
		ID:   resourceID,
		Type: graph.NodeK8sResource,
		Name: "*",
		Metadata: graph.NodeMetadata{
			ResourceKind: "*",
		},
	})

	grantEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantEdge.Metadata.Verbs = []string{"*"}
	g.AddEdge(grantEdge)

	opts := RBACAuditOptions{
		IncludeSystem: false,
		SkipChecks:    []string{"RBAC003"},
	}

	result := RunRBACAudit(g, opts)

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	for _, f := range result.Findings {
		if f.CheckID == "RBAC003" {
			t.Error("expected RBAC003 to be skipped")
		}
	}
}
