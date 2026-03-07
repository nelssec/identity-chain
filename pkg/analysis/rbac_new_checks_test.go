package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// ---------------------------------------------------------------------------
// RBAC016 – Short-lived or Custom-Audience Projected Tokens
// ---------------------------------------------------------------------------

func TestRBAC016_CustomAudienceOnEKSIRSA(t *testing.T) {
	g := graph.New()

	// SA with IRSA role ARN
	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "irsa-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "irsa-sa",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			CloudRoleARN: "arn:aws:iam::123456789012:role/my-irsa-role",
		},
	})

	// Workload using that SA with a non-standard IRSA audience
	wlID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "my-app")
	g.AddNode(&graph.Node{
		ID:        wlID,
		Type:      graph.NodeWorkload,
		Name:      "my-app",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind:           "Deployment",
			TokenAudience:          "custom-audience", // not sts.amazonaws.com
			TokenExpirationSeconds: 3600,
		},
	})
	g.AddEdge(graph.NewEdge(graph.EdgeUses, wlID, saID))

	opts := RBACAuditOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"RBAC016"},
	}

	result := RunRBACAudit(g, opts)
	if result == nil {
		t.Fatal("RunRBACAudit returned nil")
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC016" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected RBAC016 finding for IRSA SA with non-standard token audience")
	}
}

func TestRBAC016_LongLivedToken(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "long-lived-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "long-lived-sa",
		Namespace: "prod",
	})

	// Workload with a long-lived projected SA token (> 86400s = 25 hours)
	wlID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "my-app")
	g.AddNode(&graph.Node{
		ID:        wlID,
		Type:      graph.NodeWorkload,
		Name:      "my-app",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind:           "Deployment",
			TokenAudience:          "kubernetes.default.svc",
			TokenExpirationSeconds: 90000, // > 86400
		},
	})
	g.AddEdge(graph.NewEdge(graph.EdgeUses, wlID, saID))

	opts := RBACAuditOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"RBAC016"},
	}

	result := RunRBACAudit(g, opts)
	if result == nil {
		t.Fatal("RunRBACAudit returned nil")
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC016" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected RBAC016 finding for long-lived projected token (>24h)")
	}
}

func TestRBAC016_ValidToken_NoFinding(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "good-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "good-sa",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			CloudRoleARN: "arn:aws:iam::123456789012:role/good-role",
		},
	})

	// Workload with correct IRSA audience and short-lived token
	wlID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "good-app")
	g.AddNode(&graph.Node{
		ID:        wlID,
		Type:      graph.NodeWorkload,
		Name:      "good-app",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind:           "Deployment",
			TokenAudience:          "sts.amazonaws.com",
			TokenExpirationSeconds: 3600, // 1h, well within 24h
		},
	})
	g.AddEdge(graph.NewEdge(graph.EdgeUses, wlID, saID))

	opts := RBACAuditOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"RBAC016"},
	}

	result := RunRBACAudit(g, opts)
	if result == nil {
		t.Fatal("RunRBACAudit returned nil")
	}
	for _, f := range result.Findings {
		if f.CheckID == "RBAC016" {
			t.Errorf("unexpected RBAC016 finding for correctly configured IRSA token: %v", f.Description)
		}
	}
}

// ---------------------------------------------------------------------------
// RBAC017 – Projected SA Token Bypasses automountServiceAccountToken=false
// ---------------------------------------------------------------------------

func TestRBAC017_ProjectedTokenBypassesAutomount(t *testing.T) {
	g := graph.New()

	// SA with automount disabled
	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "no-automount-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "no-automount-sa",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			AutomountToken: false,
		},
	})

	// Workload that has automount=false but mounts a projected SA token
	wlID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "sneaky-app")
	g.AddNode(&graph.Node{
		ID:        wlID,
		Type:      graph.NodeWorkload,
		Name:      "sneaky-app",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind:           "Deployment",
			AutomountToken:         false, // explicitly disabled
			TokenAudience:          "kubernetes.default.svc",
			TokenExpirationSeconds: 3600,
		},
	})
	g.AddEdge(graph.NewEdge(graph.EdgeUses, wlID, saID))

	opts := RBACAuditOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"RBAC017"},
	}

	result := RunRBACAudit(g, opts)
	if result == nil {
		t.Fatal("RunRBACAudit returned nil")
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC017" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected RBAC017 finding for projected token bypassing automountServiceAccountToken=false")
	}
}

// ---------------------------------------------------------------------------
// RBAC018 – serviceaccounts/token create permission (TokenRequest abuse)
// ---------------------------------------------------------------------------

func TestRBAC018_TokenRequestAbuse_ClusterRole(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "attacker-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "attacker-sa",
		Namespace: "prod",
	})

	// Cluster-scoped role with serviceaccounts/token create
	roleID := graph.GenerateNodeID(graph.NodeRole, "", "token-creator")
	g.AddNode(&graph.Node{
		ID:   roleID,
		Type: graph.NodeRole,
		Name: "token-creator",
		Metadata: graph.NodeMetadata{
			IsClusterRole: true,
			Rules: []graph.Rule{
				{
					APIGroups: []string{""},
					Resources: []string{"serviceaccounts/token"},
					Verbs:     []string{"create"},
				},
			},
		},
	})

	g.AddEdge(graph.NewEdge(graph.EdgeBinds, saID, roleID))

	// Add the resource node so the graph can resolve grants
	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "", "serviceaccounts/token")
	g.AddNode(&graph.Node{
		ID:   resourceID,
		Type: graph.NodeK8sResource,
		Name: "serviceaccounts/token",
		Metadata: graph.NodeMetadata{
			ResourceKind: "serviceaccounts/token",
		},
	})
	grantEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantEdge.Metadata.Verbs = []string{"create"}
	g.AddEdge(grantEdge)

	opts := RBACAuditOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"RBAC018"},
	}

	result := RunRBACAudit(g, opts)
	if result == nil {
		t.Fatal("RunRBACAudit returned nil")
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC018" {
			found = true
			// Should be critical for cluster-scoped
			if f.Severity != graph.SeverityCritical {
				t.Errorf("expected SeverityCritical for cluster-scoped token creator, got %q", f.Severity)
			}
			break
		}
	}
	if !found {
		t.Error("expected RBAC018 finding for serviceaccounts/token create permission")
	}
}

func TestRBAC018_WildcardResource(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "wildcard-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "wildcard-sa",
		Namespace: "prod",
	})

	roleID := graph.GenerateNodeID(graph.NodeRole, "prod", "wildcard-role")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "wildcard-role",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			IsClusterRole: false,
			Rules: []graph.Rule{
				{
					APIGroups: []string{""},
					Resources: []string{"*"},
					Verbs:     []string{"create"},
				},
			},
		},
	})

	g.AddEdge(graph.NewEdge(graph.EdgeBinds, saID, roleID))

	// Add wildcard resource node
	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "prod", "*")
	g.AddNode(&graph.Node{
		ID:        resourceID,
		Type:      graph.NodeK8sResource,
		Name:      "*",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			ResourceKind: "*",
		},
	})
	grantEdge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	grantEdge.Metadata.Verbs = []string{"create"}
	g.AddEdge(grantEdge)

	opts := RBACAuditOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"RBAC018"},
	}

	result := RunRBACAudit(g, opts)
	if result == nil {
		t.Fatal("RunRBACAudit returned nil")
	}

	found := false
	for _, f := range result.Findings {
		if f.CheckID == "RBAC018" {
			found = true
			break
		}
	}
	if !found {
		t.Error("expected RBAC018 finding via wildcard resource (* covers serviceaccounts/token)")
	}
}

// ---------------------------------------------------------------------------
// canReadSecretsWithSeverity – namespace-scoped vs cluster-scoped severity
// ---------------------------------------------------------------------------

func TestSecretsAccessSeverity_NamespaceScoped(t *testing.T) {
	g := graph.New()

	roleID := graph.GenerateNodeID(graph.NodeRole, "prod", "ns-secret-reader")
	g.AddNode(&graph.Node{
		ID:        roleID,
		Type:      graph.NodeRole,
		Name:      "ns-secret-reader",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			IsClusterRole: false, // namespace-scoped
		},
	})

	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "prod", "secrets")
	g.AddNode(&graph.Node{
		ID:        resourceID,
		Type:      graph.NodeK8sResource,
		Name:      "secrets",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			ResourceKind: "secrets",
		},
	})

	edge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	edge.Metadata.Verbs = []string{"get", "list"}
	g.AddEdge(edge)

	roles := []*graph.Node{g.GetNode(roleID)}
	sev, found := canReadSecretsWithSeverity(g, roles)

	if !found {
		t.Fatal("expected canReadSecretsWithSeverity to return true")
	}
	if sev != graph.SeverityHigh {
		t.Errorf("expected SeverityHigh for namespace-scoped secrets access, got %q", sev)
	}
}

func TestSecretsAccessSeverity_ClusterScoped(t *testing.T) {
	g := graph.New()

	roleID := graph.GenerateNodeID(graph.NodeRole, "", "cluster-secret-reader")
	g.AddNode(&graph.Node{
		ID:   roleID,
		Type: graph.NodeRole,
		Name: "cluster-secret-reader",
		Metadata: graph.NodeMetadata{
			IsClusterRole: true, // cluster-scoped
		},
	})

	resourceID := graph.GenerateNodeID(graph.NodeK8sResource, "", "secrets")
	g.AddNode(&graph.Node{
		ID:   resourceID,
		Type: graph.NodeK8sResource,
		Name: "secrets",
		Metadata: graph.NodeMetadata{
			ResourceKind: "secrets",
		},
	})

	edge := graph.NewEdge(graph.EdgeGrants, roleID, resourceID)
	edge.Metadata.Verbs = []string{"list"}
	g.AddEdge(edge)

	roles := []*graph.Node{g.GetNode(roleID)}
	sev, found := canReadSecretsWithSeverity(g, roles)

	if !found {
		t.Fatal("expected canReadSecretsWithSeverity to return true")
	}
	if sev != graph.SeverityCritical {
		t.Errorf("expected SeverityCritical for cluster-scoped secrets access, got %q", sev)
	}
}

// ---------------------------------------------------------------------------
// ResourceName restriction reduces severity (Phase 4)
// ---------------------------------------------------------------------------

func TestClassifyEdgeSeverity_ResourceNameScoped(t *testing.T) {
	// An EdgeGrants to a secrets resource that is scoped to specific names should
	// have lower severity than an unscoped grant.
	secretNode := &graph.Node{
		ID:   graph.GenerateNodeID(graph.NodeK8sResource, "", "secrets"),
		Type: graph.NodeK8sResource,
		Name: "secrets",
		Metadata: graph.NodeMetadata{
			ResourceKind: "secrets",
		},
	}

	// Scoped edge (only a specific secret name)
	scopedEdge := &graph.Edge{
		ID:   "grants:role->secrets-scoped",
		Type: graph.EdgeGrants,
		From: "role:my-role",
		To:   secretNode.ID,
		Metadata: graph.EdgeMeta{
			Verbs:         []string{"get"},
			ResourceNames: []string{"my-specific-secret"},
		},
	}

	// Unscoped edge (all secrets)
	unscopedEdge := &graph.Edge{
		ID:   "grants:role->secrets-all",
		Type: graph.EdgeGrants,
		From: "role:my-role",
		To:   secretNode.ID,
		Metadata: graph.EdgeMeta{
			Verbs:         []string{"get"},
			ResourceNames: nil,
		},
	}

	scopedSev := graph.ClassifyEdgeSeverity(scopedEdge, secretNode)
	unscopedSev := graph.ClassifyEdgeSeverity(unscopedEdge, secretNode)

	// Scoped access should be strictly less severe than unscoped.
	severityRankMap := map[graph.Severity]int{
		graph.SeverityCritical: 4,
		graph.SeverityHigh:     3,
		graph.SeverityMedium:   2,
		graph.SeverityLow:      1,
	}

	if severityRankMap[scopedSev] >= severityRankMap[unscopedSev] {
		t.Errorf("expected scoped secrets severity (%q) to be lower than unscoped (%q)",
			scopedSev, unscopedSev)
	}
}

// ---------------------------------------------------------------------------
// Aggregated ClusterRole detection (Phase 4)
// ---------------------------------------------------------------------------

func TestAggregatedClusterRole_IsAggregatedFlag(t *testing.T) {
	g := graph.New()

	// Simulate an aggregated ClusterRole node (as AddClusterRole would create
	// when AggregationRule is present).
	aggRoleID := graph.GenerateNodeID(graph.NodeRole, "", "view")
	g.AddNode(&graph.Node{
		ID:   aggRoleID,
		Type: graph.NodeRole,
		Name: "view",
		Metadata: graph.NodeMetadata{
			IsClusterRole: true,
			IsAggregated:  true, // aggregated from child roles
		},
	})

	role := g.GetNode(aggRoleID)
	if role == nil {
		t.Fatal("failed to retrieve aggregated role node")
	}
	if !role.Metadata.IsAggregated {
		t.Error("expected IsAggregated=true for aggregated ClusterRole")
	}
}

// ---------------------------------------------------------------------------
// isSystemNamespace (Phase 1 helper)
// ---------------------------------------------------------------------------

func TestIsSystemNamespace(t *testing.T) {
	cases := []struct {
		ns       string
		expected bool
	}{
		{"kube-system", true},
		{"kube-public", true},
		{"kube-node-lease", true},
		{"default", false},
		{"prod", false},
		{"openshift-monitoring", true},
		{"cattle-system", true},
		{"fleet-default", true},
	}

	for _, tc := range cases {
		got := isSystemNamespace(tc.ns)
		if got != tc.expected {
			t.Errorf("isSystemNamespace(%q) = %v, want %v", tc.ns, got, tc.expected)
		}
	}
}

// ---------------------------------------------------------------------------
// findWorkloadsUsingSA (Phase 1 helper)
// ---------------------------------------------------------------------------

func TestFindWorkloadsUsingSA(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "my-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "my-sa",
		Namespace: "prod",
	})

	wlID := graph.GenerateNodeID(graph.NodeWorkload, "prod", "my-app")
	g.AddNode(&graph.Node{
		ID:        wlID,
		Type:      graph.NodeWorkload,
		Name:      "my-app",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "Deployment",
		},
	})

	g.AddEdge(graph.NewEdge(graph.EdgeUses, wlID, saID))

	saNode := g.GetNode(saID)
	workloads := findWorkloadsUsingSA(g, saNode)

	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload using SA, got %d", len(workloads))
	}
	if workloads[0].Name != "my-app" {
		t.Errorf("expected workload name 'my-app', got %q", workloads[0].Name)
	}
}

func TestFindWorkloadsUsingSA_NoWorkloads(t *testing.T) {
	g := graph.New()

	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "prod", "orphan-sa")
	g.AddNode(&graph.Node{
		ID:        saID,
		Type:      graph.NodeServiceAccount,
		Name:      "orphan-sa",
		Namespace: "prod",
	})

	saNode := g.GetNode(saID)
	workloads := findWorkloadsUsingSA(g, saNode)

	if len(workloads) != 0 {
		t.Errorf("expected 0 workloads for orphaned SA, got %d", len(workloads))
	}
}
