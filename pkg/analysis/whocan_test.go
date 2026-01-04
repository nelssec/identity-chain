package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestWhoCan_NoMatch(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "default", "app-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "app-sa",
		Namespace: "default",
	})

	roleID := graph.GenerateNodeID(graph.NodeRole, "default", "reader")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "reader",
		Namespace: "default",
	})

	bindEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindEdge)

	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "", "configmaps")
	g.AddNode(&graph.Node{
		ID:   resourceID,
		Type: graph.NodeK8sResource,
		Name: "configmaps",
		Metadata: graph.NodeMetadata{
			ResourceKind: "configmaps",
		},
	})

	grantEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantEdge.Metadata.Verbs = []string{"get", "list"}
	g.AddEdge(grantEdge)

	query := WhoCanQuery{
		Verb:     "delete",
		Resource: "secrets",
	}

	result, err := WhoCan(g, query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalCount != 0 {
		t.Errorf("expected 0 subjects, got %d", result.TotalCount)
	}
}

func TestWhoCan_Match(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "default", "secret-reader")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "secret-reader",
		Namespace: "default",
	})

	roleID := graph.GenerateNodeID(graph.NodeRole, "default", "secret-role")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "secret-role",
		Namespace: "default",
	})

	bindEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	bindEdge.Metadata.BindingName = "secret-binding"
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

	query := WhoCanQuery{
		Verb:     "get",
		Resource: "secrets",
	}

	result, err := WhoCan(g, query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result.TotalCount != 1 {
		t.Errorf("expected 1 subject, got %d", result.TotalCount)
	}

	if len(result.Subjects) != 1 {
		t.Fatalf("expected 1 subject in list, got %d", len(result.Subjects))
	}

	if result.Subjects[0].Name != "secret-reader" {
		t.Errorf("expected subject name 'secret-reader', got '%s'", result.Subjects[0].Name)
	}
}

func TestWhatCan_NoPermissions(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "default", "empty-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "empty-sa",
		Namespace: "default",
	})

	query := ReverseRBACQuery{
		SubjectKind: "ServiceAccount",
		SubjectName: "empty-sa",
		Namespace:   "default",
	}

	result, err := WhatCan(g, query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Permissions) != 0 {
		t.Errorf("expected 0 permissions, got %d", len(result.Permissions))
	}
}

func TestWhatCan_WithPermissions(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "default", "admin-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "admin-sa",
		Namespace: "default",
	})

	roleID := graph.GenerateNodeID(graph.NodeRole, "default", "admin-role")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "admin-role",
		Namespace: "default",
	})

	bindEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindEdge)

	secretsID := graph.GenerateNodeID(graph.NodeK8sResource, "", "secrets")
	g.AddNode(&graph.Node{
		ID:   secretsID,
		Type: graph.NodeK8sResource,
		Name: "secrets",
		Metadata: graph.NodeMetadata{
			ResourceKind: "secrets",
		},
	})

	grantEdge := graph.NewEdge(graph.EdgeGrants, roleID, secretsID)
	grantEdge.Metadata.Verbs = []string{"get", "list", "create", "delete"}
	g.AddEdge(grantEdge)

	podsID := graph.GenerateNodeID(graph.NodeK8sResource, "", "pods")
	g.AddNode(&graph.Node{
		ID:   podsID,
		Type: graph.NodeK8sResource,
		Name: "pods",
		Metadata: graph.NodeMetadata{
			ResourceKind: "pods",
		},
	})

	grantEdge2 := graph.NewEdge(graph.EdgeGrants, roleID, podsID)
	grantEdge2.Metadata.Verbs = []string{"get", "list"}
	g.AddEdge(grantEdge2)

	query := ReverseRBACQuery{
		SubjectKind: "ServiceAccount",
		SubjectName: "admin-sa",
		Namespace:   "default",
	}

	result, err := WhatCan(g, query)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if len(result.Permissions) != 2 {
		t.Errorf("expected 2 permissions, got %d", len(result.Permissions))
	}

	if result.TotalVerbs != 6 {
		t.Errorf("expected 6 total verbs, got %d", result.TotalVerbs)
	}
}
