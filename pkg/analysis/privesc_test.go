package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestFindPrivescPaths_NoPrivesc(t *testing.T) {
	g := graph.New()

	workloadID := graph.GenerateNodeID(graph.NodeWorkload, "default", "app")
	g.AddNode(&graph.Node{
		ID:        workloadID,
		Type:      graph.NodeWorkload,
		Name:      "app",
		Namespace: "default",
	})

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "default", "app-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "app-sa",
		Namespace: "default",
	})

	g.AddEdge(graph.NewEdge(graph.EdgeUses, workloadID, saID))

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

	result, err := FindPrivescPaths(g, workloadID, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if len(result.DirectVectors) != 0 {
		t.Errorf("expected no direct vectors, got %d", len(result.DirectVectors))
	}
}

func TestFindPrivescPaths_WithBindRoles(t *testing.T) {
	g := graph.New()

	workloadID := graph.GenerateNodeID(graph.NodeWorkload, "default", "app")
	g.AddNode(&graph.Node{
		ID:        workloadID,
		Type:      graph.NodeWorkload,
		Name:      "app",
		Namespace: "default",
	})

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "default", "admin-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "admin-sa",
		Namespace: "default",
	})

	g.AddEdge(graph.NewEdge(graph.EdgeUses, workloadID, saID))

	roleID := graph.GenerateNodeID(graph.NodeRole, "default", "rbac-admin")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "rbac-admin",
		Namespace: "default",
	})

	bindEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindEdge)

	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "", "rolebindings")
	g.AddNode(&graph.Node{
		ID:   resourceID,
		Type: graph.NodeK8sResource,
		Name: "rolebindings",
		Metadata: graph.NodeMetadata{
			ResourceKind: "rolebindings",
		},
	})

	grantEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantEdge.Metadata.Verbs = []string{"create", "update", "delete"}
	g.AddEdge(grantEdge)

	result, err := FindPrivescPaths(g, workloadID, 3)
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}

	if result == nil {
		t.Fatal("expected result, got nil")
	}

	if len(result.DirectVectors) == 0 {
		t.Error("expected at least one privesc vector for rolebindings create")
	}

	foundBindRoles := false
	for _, v := range result.DirectVectors {
		if v.Vector == VectorBindRoles {
			foundBindRoles = true
			break
		}
	}

	if !foundBindRoles {
		t.Error("expected to find bind_roles vector")
	}
}

func TestSummarizePrivescResults(t *testing.T) {
	results := []*PrivescResult{
		{
			MaxSeverity: graph.SeverityCritical,
			DirectVectors: []DirectVector{
				{Vector: VectorBindRoles, Severity: graph.SeverityCritical},
				{Vector: VectorEscalateVerb, Severity: graph.SeverityCritical},
			},
		},
		{
			MaxSeverity: graph.SeverityHigh,
			DirectVectors: []DirectVector{
				{Vector: VectorCreatePods, Severity: graph.SeverityHigh},
			},
		},
	}

	summary := SummarizePrivescResults(results)

	if summary.WorkloadsWithPrivesc != 2 {
		t.Errorf("expected 2 workloads with privesc, got %d", summary.WorkloadsWithPrivesc)
	}

	if summary.CriticalPaths != 2 {
		t.Errorf("expected 2 critical paths, got %d", summary.CriticalPaths)
	}

	if summary.HighPaths != 1 {
		t.Errorf("expected 1 high path, got %d", summary.HighPaths)
	}
}
