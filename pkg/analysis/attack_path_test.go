package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestFindAttackPaths_SecretsAccess(t *testing.T) {
	// Create a graph with a workload that can read secrets
	g := graph.New()

	// Add workload
	workloadID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "api-server")
	workloadNode := graph.NewNode(graph.NodeWorkload, "prod", "api-server")
	workloadNode.Metadata.WorkloadKind = "Deployment"
	g.AddNode(workloadNode)

	// Add service account
	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "api-sa")
	saNode := graph.NewNode(graph.NodeServiceAccount, "prod", "api-sa")
	g.AddNode(saNode)

	// Add role with secrets access
	roleID := graph.GenerateNodeID(graph.NodeRole, "prod", "secret-reader")
	roleNode := graph.NewNode(graph.NodeRole, "prod", "secret-reader")
	g.AddNode(roleNode)

	// Add resource with secrets access
	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "prod", "secrets")
	secretNode := graph.NewNode(graph.NodeK8sResource, "prod", "secrets")
	secretNode.Metadata.ResourceKind = "secrets"
	g.AddNode(secretNode)

	// Connect workload to SA
	usesEdge := graph.NewEdge(graph.EdgeUses, workloadID, saID)
	g.AddEdge(usesEdge)

	// Bind SA to role
	bindsEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindsEdge)

	// Grant secrets access
	grantsEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantsEdge.Metadata.Verbs = []string{"get", "list"}
	g.AddEdge(grantsEdge)

	// Run attack path analysis
	opts := AttackPathOptions{
		MaxDepth:       5,
		IncludePrivesc: true,
	}

	result, err := FindAttackPaths(g, workloadID, opts)
	if err != nil {
		t.Fatalf("FindAttackPaths failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Should find a secrets access path
	found := false
	for _, path := range result.Paths {
		if path.Objective == "Read Kubernetes Secrets" {
			found = true
			if path.MaxSeverity != graph.SeverityCritical {
				t.Errorf("Expected critical severity for secrets access, got %s", path.MaxSeverity)
			}
			if len(path.Steps) < 2 {
				t.Errorf("Expected at least 2 steps, got %d", len(path.Steps))
			}
			break
		}
	}

	if !found {
		t.Errorf("Expected to find secrets access path, found paths: %d", len(result.Paths))
		for _, p := range result.Paths {
			t.Logf("  Path: %s -> %s", p.Name, p.Objective)
		}
	}
}

func TestFindAttackPaths_PodExec(t *testing.T) {
	// Create a graph with a workload that can exec into pods
	g := graph.New()

	// Add workload
	workloadID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "admin-pod")
	workloadNode := graph.NewNode(graph.NodeWorkload, "prod", "admin-pod")
	workloadNode.Metadata.WorkloadKind = "Deployment"
	g.AddNode(workloadNode)

	// Add service account
	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "admin-sa")
	saNode := graph.NewNode(graph.NodeServiceAccount, "prod", "admin-sa")
	g.AddNode(saNode)

	// Add role with pod exec access
	roleID := graph.GenerateNodeID(graph.NodeRole, "prod", "pod-exec")
	roleNode := graph.NewNode(graph.NodeRole, "prod", "pod-exec")
	g.AddNode(roleNode)

	// Add resource with pods/exec access
	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "prod", "pods/exec")
	execNode := graph.NewNode(graph.NodeK8sResource, "prod", "pods/exec")
	execNode.Metadata.ResourceKind = "pods/exec"
	g.AddNode(execNode)

	// Connect workload to SA
	usesEdge := graph.NewEdge(graph.EdgeUses, workloadID, saID)
	g.AddEdge(usesEdge)

	// Bind SA to role
	bindsEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindsEdge)

	// Grant exec access
	grantsEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantsEdge.Metadata.Verbs = []string{"create", "get"}
	g.AddEdge(grantsEdge)

	// Run attack path analysis
	opts := AttackPathOptions{
		MaxDepth:       5,
		IncludePrivesc: true,
	}

	result, err := FindAttackPaths(g, workloadID, opts)
	if err != nil {
		t.Fatalf("FindAttackPaths failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Should find a pod exec path
	found := false
	for _, path := range result.Paths {
		if path.Objective == "Lateral Movement to Other Pods" {
			found = true
			if path.MaxSeverity != graph.SeverityHigh {
				t.Errorf("Expected high severity for pod exec, got %s", path.MaxSeverity)
			}
			break
		}
	}

	if !found {
		t.Errorf("Expected to find pod exec path, found paths: %d", len(result.Paths))
		for _, p := range result.Paths {
			t.Logf("  Path: %s -> %s", p.Name, p.Objective)
		}
	}
}

func TestFindAttackPaths_PrivilegeEscalation(t *testing.T) {
	// Create a graph with a workload that can create rolebindings
	g := graph.New()

	// Add workload
	workloadID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "privesc-pod")
	workloadNode := graph.NewNode(graph.NodeWorkload, "prod", "privesc-pod")
	workloadNode.Metadata.WorkloadKind = "Deployment"
	g.AddNode(workloadNode)

	// Add service account
	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "privesc-sa")
	saNode := graph.NewNode(graph.NodeServiceAccount, "prod", "privesc-sa")
	g.AddNode(saNode)

	// Add role with rolebindings create access
	roleID := graph.GenerateNodeID(graph.NodeRole, "prod", "rbac-modifier")
	roleNode := graph.NewNode(graph.NodeRole, "prod", "rbac-modifier")
	g.AddNode(roleNode)

	// Add resource with rolebindings access
	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "prod", "rolebindings")
	rbNode := graph.NewNode(graph.NodeK8sResource, "prod", "rolebindings")
	rbNode.Metadata.ResourceKind = "rolebindings"
	g.AddNode(rbNode)

	// Connect workload to SA
	usesEdge := graph.NewEdge(graph.EdgeUses, workloadID, saID)
	g.AddEdge(usesEdge)

	// Bind SA to role
	bindsEdge := graph.NewEdge(graph.EdgeBinds, saID, roleID)
	g.AddEdge(bindsEdge)

	// Grant rolebindings create access
	grantsEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantsEdge.Metadata.Verbs = []string{"create", "update"}
	g.AddEdge(grantsEdge)

	// Run attack path analysis
	opts := AttackPathOptions{
		MaxDepth:       5,
		IncludePrivesc: true,
	}

	result, err := FindAttackPaths(g, workloadID, opts)
	if err != nil {
		t.Fatalf("FindAttackPaths failed: %v", err)
	}

	if result == nil {
		t.Fatal("Expected result, got nil")
	}

	// Should find a privilege escalation path
	found := false
	for _, path := range result.Paths {
		if path.Objective == "Cluster Admin Access" {
			found = true
			if path.MaxSeverity != graph.SeverityCritical {
				t.Errorf("Expected critical severity for privesc, got %s", path.MaxSeverity)
			}
			if !path.AffectsCluster {
				t.Error("Expected path to affect cluster")
			}
			break
		}
	}

	if !found {
		t.Errorf("Expected to find privilege escalation path, found paths: %d", len(result.Paths))
		for _, p := range result.Paths {
			t.Logf("  Path: %s -> %s (severity: %s)", p.Name, p.Objective, p.MaxSeverity)
		}
	}
}

func TestFindAllAttackPaths(t *testing.T) {
	// Create a graph with multiple workloads
	g := graph.New()

	// Add workload 1 with secrets access
	workload1ID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "app1")
	workload1Node := graph.NewNode(graph.NodeWorkload, "prod", "app1")
	workload1Node.Metadata.WorkloadKind = "Deployment"
	g.AddNode(workload1Node)

	sa1ID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "sa1")
	sa1Node := graph.NewNode(graph.NodeServiceAccount, "prod", "sa1")
	g.AddNode(sa1Node)

	role1ID := graph.GenerateNodeID(graph.NodeRole, "prod", "role1")
	role1Node := graph.NewNode(graph.NodeRole, "prod", "role1")
	g.AddNode(role1Node)

	secret1ID := graph.GenerateNodeID(graph.NodeK8sResource, "prod", "secrets")
	secretNode := graph.NewNode(graph.NodeK8sResource, "prod", "secrets")
	secretNode.Metadata.ResourceKind = "secrets"
	g.AddNode(secretNode)

	uses1Edge := graph.NewEdge(graph.EdgeUses, workload1ID, sa1ID)
	g.AddEdge(uses1Edge)

	binds1Edge := graph.NewEdge(graph.EdgeBinds, sa1ID, role1ID)
	g.AddEdge(binds1Edge)

	grants1Edge := graph.NewEdge(graph.EdgeGrants, role1ID, secret1ID)
	grants1Edge.Metadata.Verbs = []string{"get"}
	g.AddEdge(grants1Edge)

	// Add workload 2 without sensitive access
	workload2ID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "app2")
	workload2Node := graph.NewNode(graph.NodeWorkload, "prod", "app2")
	workload2Node.Metadata.WorkloadKind = "Deployment"
	g.AddNode(workload2Node)

	sa2ID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "sa2")
	sa2Node := graph.NewNode(graph.NodeServiceAccount, "prod", "sa2")
	g.AddNode(sa2Node)

	role2ID := graph.GenerateNodeID(graph.NodeRole, "prod", "role2")
	role2Node := graph.NewNode(graph.NodeRole, "prod", "role2")
	g.AddNode(role2Node)

	cm2ID := graph.GenerateNodeID(graph.NodeK8sResource, "prod", "configmaps")
	cmNode := graph.NewNode(graph.NodeK8sResource, "prod", "configmaps")
	cmNode.Metadata.ResourceKind = "configmaps"
	g.AddNode(cmNode)

	uses2Edge := graph.NewEdge(graph.EdgeUses, workload2ID, sa2ID)
	g.AddEdge(uses2Edge)

	binds2Edge := graph.NewEdge(graph.EdgeBinds, sa2ID, role2ID)
	g.AddEdge(binds2Edge)

	grants2Edge := graph.NewEdge(graph.EdgeGrants, role2ID, cm2ID)
	grants2Edge.Metadata.Verbs = []string{"get"}
	g.AddEdge(grants2Edge)

	// Run analysis on all workloads
	opts := AttackPathOptions{
		MaxDepth:       5,
		IncludePrivesc: true,
	}

	results, err := FindAllAttackPaths(g, opts)
	if err != nil {
		t.Fatalf("FindAllAttackPaths failed: %v", err)
	}

	// Should find at least 1 result (workload with secrets access)
	if len(results) == 0 {
		t.Error("Expected at least one result")
	}

	// The workload with secrets access should have paths
	foundSecretsPath := false
	for _, r := range results {
		for _, p := range r.Paths {
			if p.Objective == "Read Kubernetes Secrets" {
				foundSecretsPath = true
				break
			}
		}
	}

	if !foundSecretsPath {
		t.Error("Expected to find secrets access path in results")
	}
}

func TestSummarizeAttackPaths(t *testing.T) {
	results := []*AttackPathResult{
		{
			SourceWorkload: &graph.Node{Name: "app1", Namespace: "prod"},
			TotalPaths:     3,
			CriticalPaths:  1,
			HighPaths:      2,
			Paths: []*AttackPath{
				{
					Name:         "Secrets Access",
					Objective:    "Read Kubernetes Secrets",
					MaxSeverity:  graph.SeverityCritical,
					AffectsCloud: false,
					Steps: []AttackPathStep{
						{Technique: TechniqueSecretsAccess},
					},
				},
				{
					Name:         "Cloud Access",
					Objective:    "Access Cloud Resources",
					MaxSeverity:  graph.SeverityHigh,
					AffectsCloud: true,
					Steps: []AttackPathStep{
						{Technique: TechniqueCloudAccess},
					},
				},
			},
		},
		{
			SourceWorkload: &graph.Node{Name: "app2", Namespace: "prod"},
			TotalPaths:     1,
			CriticalPaths:  0,
			HighPaths:      1,
			Paths: []*AttackPath{
				{
					Name:           "Pod Exec",
					Objective:      "Lateral Movement to Other Pods",
					MaxSeverity:    graph.SeverityHigh,
					AffectsCluster: true,
					Steps: []AttackPathStep{
						{Technique: TechniquePodExec},
					},
				},
			},
		},
	}

	summary := SummarizeAttackPaths(results)

	if summary.TotalWorkloads != 2 {
		t.Errorf("Expected 2 total workloads, got %d", summary.TotalWorkloads)
	}

	if summary.WorkloadsWithPaths != 2 {
		t.Errorf("Expected 2 workloads with paths, got %d", summary.WorkloadsWithPaths)
	}

	if summary.TotalPaths != 4 {
		t.Errorf("Expected 4 total paths, got %d", summary.TotalPaths)
	}

	if summary.CriticalPaths != 1 {
		t.Errorf("Expected 1 critical path, got %d", summary.CriticalPaths)
	}

	if summary.HighPaths != 3 {
		t.Errorf("Expected 3 high paths, got %d", summary.HighPaths)
	}

	if summary.CloudPaths != 1 {
		t.Errorf("Expected 1 cloud path, got %d", summary.CloudPaths)
	}

	if summary.ClusterPaths != 1 {
		t.Errorf("Expected 1 cluster path, got %d", summary.ClusterPaths)
	}

	if len(summary.TopTechniques) == 0 {
		t.Error("Expected at least one technique in summary")
	}

	if len(summary.TopObjectives) == 0 {
		t.Error("Expected at least one objective in summary")
	}
}
