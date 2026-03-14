package graph

import (
	"strings"
	"testing"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/util/intstr"
)

// ---------------------------------------------------------------------------
// node.go tests
// ---------------------------------------------------------------------------

func TestNewNode(t *testing.T) {
	tests := []struct {
		name      string
		nodeType  NodeType
		namespace string
		nodeName  string
		wantID    string
	}{
		{
			name:      "namespaced node",
			nodeType:  NodeServiceAccount,
			namespace: "default",
			nodeName:  "my-sa",
			wantID:    "service_account:default/my-sa",
		},
		{
			name:      "cluster-scoped node",
			nodeType:  NodeRole,
			namespace: "",
			nodeName:  "cluster-admin",
			wantID:    "role:cluster-admin",
		},
		{
			name:      "workload node",
			nodeType:  NodeWorkload,
			namespace: "prod",
			nodeName:  "api-server",
			wantID:    "workload:prod/api-server",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNode(tt.nodeType, tt.namespace, tt.nodeName)
			if n.ID != tt.wantID {
				t.Errorf("ID = %q, want %q", n.ID, tt.wantID)
			}
			if n.Type != tt.nodeType {
				t.Errorf("Type = %q, want %q", n.Type, tt.nodeType)
			}
			if n.Namespace != tt.namespace {
				t.Errorf("Namespace = %q, want %q", n.Namespace, tt.namespace)
			}
			if n.Name != tt.nodeName {
				t.Errorf("Name = %q, want %q", n.Name, tt.nodeName)
			}
			if n.Labels == nil {
				t.Error("Labels map should be initialized")
			}
		})
	}
}

func TestGenerateNodeID(t *testing.T) {
	tests := []struct {
		name      string
		nodeType  NodeType
		namespace string
		nodeName  string
		want      string
	}{
		{"with namespace", NodeServiceAccount, "ns", "sa", "service_account:ns/sa"},
		{"without namespace", NodeRole, "", "admin", "role:admin"},
		{"cloud role", NodeCloudRole, "", "arn:aws:iam::123:role/myrole", "cloud_role:arn:aws:iam::123:role/myrole"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateNodeID(tt.nodeType, tt.namespace, tt.nodeName)
			if got != tt.want {
				t.Errorf("GenerateNodeID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestIsClusterScoped(t *testing.T) {
	tests := []struct {
		name      string
		namespace string
		want      bool
	}{
		{"cluster-scoped", "", true},
		{"namespaced", "default", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNode(NodeRole, tt.namespace, "test")
			if got := n.IsClusterScoped(); got != tt.want {
				t.Errorf("IsClusterScoped() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestHasCloudIdentity(t *testing.T) {
	tests := []struct {
		name     string
		nodeType NodeType
		metadata NodeMetadata
		want     bool
	}{
		{
			name:     "SA with AWS ARN",
			nodeType: NodeServiceAccount,
			metadata: NodeMetadata{CloudRoleARN: "arn:aws:iam::123:role/r"},
			want:     true,
		},
		{
			name:     "SA with GCP SA",
			nodeType: NodeServiceAccount,
			metadata: NodeMetadata{GCPServiceAccount: "sa@proj.iam.gserviceaccount.com"},
			want:     true,
		},
		{
			name:     "SA with Azure ID",
			nodeType: NodeServiceAccount,
			metadata: NodeMetadata{AzureManagedID: "some-client-id"},
			want:     true,
		},
		{
			name:     "SA without cloud identity",
			nodeType: NodeServiceAccount,
			metadata: NodeMetadata{},
			want:     false,
		},
		{
			name:     "non-SA node with ARN",
			nodeType: NodeWorkload,
			metadata: NodeMetadata{CloudRoleARN: "arn:aws:iam::123:role/r"},
			want:     false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			n := NewNode(tt.nodeType, "default", "test")
			n.Metadata = tt.metadata
			if got := n.HasCloudIdentity(); got != tt.want {
				t.Errorf("HasCloudIdentity() = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// edge.go tests
// ---------------------------------------------------------------------------

func TestNewEdge(t *testing.T) {
	e := NewEdge(EdgeBinds, "sa:default/mysa", "role:myrole")
	wantID := "binds:sa:default/mysa->role:myrole"
	if e.ID != wantID {
		t.Errorf("ID = %q, want %q", e.ID, wantID)
	}
	if e.Type != EdgeBinds {
		t.Errorf("Type = %q, want %q", e.Type, EdgeBinds)
	}
	if e.From != "sa:default/mysa" {
		t.Errorf("From = %q", e.From)
	}
	if e.To != "role:myrole" {
		t.Errorf("To = %q", e.To)
	}
}

func TestGenerateEdgeID(t *testing.T) {
	tests := []struct {
		name     string
		edgeType EdgeType
		from, to string
		want     string
	}{
		{"binds", EdgeBinds, "A", "B", "binds:A->B"},
		{"uses", EdgeUses, "X", "Y", "uses:X->Y"},
		{"grants", EdgeGrants, "R", "Res", "grants:R->Res"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := GenerateEdgeID(tt.edgeType, tt.from, tt.to)
			if got != tt.want {
				t.Errorf("GenerateEdgeID() = %q, want %q", got, tt.want)
			}
		})
	}
}

func TestClassifyEdgeSeverity(t *testing.T) {
	tests := []struct {
		name       string
		edge       *Edge
		targetNode *Node
		want       Severity
	}{
		{
			name: "grants secrets unscoped -> critical",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"get", "list"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "secrets"}},
			want:       SeverityCritical,
		},
		{
			name: "grants secrets scoped by name -> high",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"get"}, ResourceNames: []string{"my-secret"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "secrets"}},
			want:       SeverityHigh,
		},
		{
			name: "grants pods with dangerous verb unscoped -> high",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"create"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "pods"}},
			want:       SeverityHigh,
		},
		{
			name: "grants pods with dangerous verb scoped -> medium",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"delete"}, ResourceNames: []string{"my-pod"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "pods"}},
			want:       SeverityMedium,
		},
		{
			name: "grants deployments with wildcard verb unscoped -> high",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"*"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "deployments"}},
			want:       SeverityHigh,
		},
		{
			name: "grants configmaps with dangerous verb unscoped -> medium",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"update"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "configmaps"}},
			want:       SeverityMedium,
		},
		{
			name: "grants configmaps with dangerous verb scoped -> low",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"patch"}, ResourceNames: []string{"cm1"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "configmaps"}},
			want:       SeverityLow,
		},
		{
			name: "grants configmaps read-only -> low (default)",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"get", "list"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "configmaps"}},
			want:       SeverityLow,
		},
		{
			name: "grants pods read-only -> low (default)",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"get"}},
			},
			targetNode: &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: "pods"}},
			want:       SeverityLow,
		},
		{
			name: "grants with nil target -> low",
			edge: &Edge{
				Type:     EdgeGrants,
				Metadata: EdgeMeta{Verbs: []string{"create"}},
			},
			targetNode: nil,
			want:       SeverityLow,
		},
		{
			name: "assumes edge -> high",
			edge: &Edge{Type: EdgeAssumes},
			want: SeverityHigh,
		},
		{
			name: "allows edge wildcard -> critical",
			edge: &Edge{
				Type:     EdgeAllows,
				Metadata: EdgeMeta{Actions: []string{"*"}},
			},
			want: SeverityCritical,
		},
		{
			name: "allows edge star:star -> critical",
			edge: &Edge{
				Type:     EdgeAllows,
				Metadata: EdgeMeta{Actions: []string{"s3:GetObject", "*:*"}},
			},
			want: SeverityCritical,
		},
		{
			name: "allows edge normal -> high",
			edge: &Edge{
				Type:     EdgeAllows,
				Metadata: EdgeMeta{Actions: []string{"s3:GetObject"}},
			},
			want: SeverityHigh,
		},
		{
			name: "uses edge -> low",
			edge: &Edge{Type: EdgeUses},
			want: SeverityLow,
		},
		{
			name: "binds edge -> low",
			edge: &Edge{Type: EdgeBinds},
			want: SeverityLow,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := ClassifyEdgeSeverity(tt.edge, tt.targetNode)
			if got != tt.want {
				t.Errorf("ClassifyEdgeSeverity() = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// graph.go tests
// ---------------------------------------------------------------------------

func TestGraphNew(t *testing.T) {
	g := New()
	if g == nil {
		t.Fatal("New() returned nil")
	}
	stats := g.Stats()
	if stats.TotalNodes != 0 || stats.TotalEdges != 0 {
		t.Errorf("new graph should be empty, got %d nodes, %d edges", stats.TotalNodes, stats.TotalEdges)
	}
}

func TestGraphAddNode(t *testing.T) {
	g := New()
	n := NewNode(NodeServiceAccount, "default", "test-sa")

	if err := g.AddNode(n); err != nil {
		t.Fatalf("AddNode() unexpected error: %v", err)
	}

	// Verify retrieval
	got := g.GetNode(n.ID)
	if got != n {
		t.Error("GetNode() did not return the added node")
	}

	// Duplicate should error
	if err := g.AddNode(n); err == nil {
		t.Error("AddNode() duplicate should return error")
	}
}

func TestGraphAddEdge(t *testing.T) {
	g := New()
	n1 := NewNode(NodeWorkload, "default", "dep1")
	n2 := NewNode(NodeServiceAccount, "default", "sa1")
	_ = g.AddNode(n1)
	_ = g.AddNode(n2)

	e := NewEdge(EdgeUses, n1.ID, n2.ID)
	if err := g.AddEdge(e); err != nil {
		t.Fatalf("AddEdge() unexpected error: %v", err)
	}

	// Duplicate edge should silently succeed (no error)
	if err := g.AddEdge(e); err != nil {
		t.Errorf("AddEdge() duplicate should return nil, got: %v", err)
	}

	// Edge with missing source
	eBadSrc := NewEdge(EdgeUses, "nonexistent", n2.ID)
	if err := g.AddEdge(eBadSrc); err == nil {
		t.Error("AddEdge() with missing source should error")
	}

	// Edge with missing target
	eBadTgt := NewEdge(EdgeUses, n1.ID, "nonexistent")
	if err := g.AddEdge(eBadTgt); err == nil {
		t.Error("AddEdge() with missing target should error")
	}
}

func TestGraphGetNodesByType(t *testing.T) {
	g := New()
	sa1 := NewNode(NodeServiceAccount, "ns1", "sa1")
	sa2 := NewNode(NodeServiceAccount, "ns2", "sa2")
	wl := NewNode(NodeWorkload, "ns1", "dep1")
	_ = g.AddNode(sa1)
	_ = g.AddNode(sa2)
	_ = g.AddNode(wl)

	sas := g.GetNodesByType(NodeServiceAccount)
	if len(sas) != 2 {
		t.Errorf("expected 2 SAs, got %d", len(sas))
	}
	wls := g.GetNodesByType(NodeWorkload)
	if len(wls) != 1 {
		t.Errorf("expected 1 workload, got %d", len(wls))
	}
	empty := g.GetNodesByType(NodeCloudRole)
	if len(empty) != 0 {
		t.Errorf("expected 0 cloud roles, got %d", len(empty))
	}
}

func TestGraphGetNodesByNamespace(t *testing.T) {
	g := New()
	_ = g.AddNode(NewNode(NodeServiceAccount, "ns1", "sa1"))
	_ = g.AddNode(NewNode(NodeWorkload, "ns1", "dep1"))
	_ = g.AddNode(NewNode(NodeServiceAccount, "ns2", "sa2"))
	_ = g.AddNode(NewNode(NodeRole, "", "cluster-admin")) // cluster-scoped

	ns1Nodes := g.GetNodesByNamespace("ns1")
	if len(ns1Nodes) != 2 {
		t.Errorf("expected 2 nodes in ns1, got %d", len(ns1Nodes))
	}

	ns2Nodes := g.GetNodesByNamespace("ns2")
	if len(ns2Nodes) != 1 {
		t.Errorf("expected 1 node in ns2, got %d", len(ns2Nodes))
	}

	// Cluster-scoped nodes should not appear in any namespace
	emptyNS := g.GetNodesByNamespace("")
	if len(emptyNS) != 0 {
		t.Errorf("expected 0 nodes for empty namespace, got %d", len(emptyNS))
	}
}

func TestGraphOutAndInEdges(t *testing.T) {
	g := New()
	n1 := NewNode(NodeWorkload, "ns", "dep")
	n2 := NewNode(NodeServiceAccount, "ns", "sa")
	n3 := NewNode(NodeRole, "ns", "role")
	_ = g.AddNode(n1)
	_ = g.AddNode(n2)
	_ = g.AddNode(n3)

	e1 := NewEdge(EdgeUses, n1.ID, n2.ID)
	e2 := NewEdge(EdgeBinds, n2.ID, n3.ID)
	_ = g.AddEdge(e1)
	_ = g.AddEdge(e2)

	outN1 := g.GetOutEdges(n1.ID)
	if len(outN1) != 1 || outN1[0].To != n2.ID {
		t.Errorf("GetOutEdges(n1) = %v", outN1)
	}

	inN2 := g.GetInEdges(n2.ID)
	if len(inN2) != 1 || inN2[0].From != n1.ID {
		t.Errorf("GetInEdges(n2) = %v", inN2)
	}

	outN2 := g.GetOutEdges(n2.ID)
	if len(outN2) != 1 || outN2[0].To != n3.ID {
		t.Errorf("GetOutEdges(n2) = %v", outN2)
	}

	inN3 := g.GetInEdges(n3.ID)
	if len(inN3) != 1 || inN3[0].From != n2.ID {
		t.Errorf("GetInEdges(n3) = %v", inN3)
	}
}

func TestGraphFindNode(t *testing.T) {
	g := New()
	n := NewNode(NodeServiceAccount, "default", "my-sa")
	_ = g.AddNode(n)

	found := g.FindNode(NodeServiceAccount, "default", "my-sa")
	if found != n {
		t.Error("FindNode() did not return expected node")
	}

	missing := g.FindNode(NodeServiceAccount, "default", "other-sa")
	if missing != nil {
		t.Error("FindNode() should return nil for missing node")
	}
}

func TestGraphStats(t *testing.T) {
	g := New()
	sa := NewNode(NodeServiceAccount, "ns", "sa")
	wl := NewNode(NodeWorkload, "ns", "dep")
	role := NewNode(NodeRole, "", "admin")
	_ = g.AddNode(sa)
	_ = g.AddNode(wl)
	_ = g.AddNode(role)

	e1 := NewEdge(EdgeUses, wl.ID, sa.ID)
	e2 := NewEdge(EdgeBinds, sa.ID, role.ID)
	_ = g.AddEdge(e1)
	_ = g.AddEdge(e2)

	stats := g.Stats()
	if stats.TotalNodes != 3 {
		t.Errorf("TotalNodes = %d, want 3", stats.TotalNodes)
	}
	if stats.TotalEdges != 2 {
		t.Errorf("TotalEdges = %d, want 2", stats.TotalEdges)
	}
	if stats.NodeCounts[NodeServiceAccount] != 1 {
		t.Errorf("SA count = %d, want 1", stats.NodeCounts[NodeServiceAccount])
	}
	if stats.EdgeCounts[EdgeUses] != 1 {
		t.Errorf("Uses edge count = %d, want 1", stats.EdgeCounts[EdgeUses])
	}
}

func TestGraphAllNodesAndEdges(t *testing.T) {
	g := New()
	n1 := NewNode(NodeServiceAccount, "ns", "sa")
	n2 := NewNode(NodeWorkload, "ns", "dep")
	_ = g.AddNode(n1)
	_ = g.AddNode(n2)

	e := NewEdge(EdgeUses, n2.ID, n1.ID)
	_ = g.AddEdge(e)

	allNodes := g.AllNodes()
	if len(allNodes) != 2 {
		t.Errorf("AllNodes() len = %d, want 2", len(allNodes))
	}

	allEdges := g.AllEdges()
	if len(allEdges) != 1 {
		t.Errorf("AllEdges() len = %d, want 1", len(allEdges))
	}
}

func TestGraphGetWorkloadsUsingSA(t *testing.T) {
	g := New()
	sa := NewNode(NodeServiceAccount, "ns", "sa")
	dep1 := NewNode(NodeWorkload, "ns", "dep1")
	dep2 := NewNode(NodeWorkload, "ns", "dep2")
	_ = g.AddNode(sa)
	_ = g.AddNode(dep1)
	_ = g.AddNode(dep2)

	_ = g.AddEdge(NewEdge(EdgeUses, dep1.ID, sa.ID))
	_ = g.AddEdge(NewEdge(EdgeUses, dep2.ID, sa.ID))

	workloads := g.GetWorkloadsUsingSA(sa.ID)
	if len(workloads) != 2 {
		t.Errorf("GetWorkloadsUsingSA() returned %d workloads, want 2", len(workloads))
	}

	// Non-EdgeUses edges should not be tracked
	role := NewNode(NodeRole, "", "r")
	_ = g.AddNode(role)
	_ = g.AddEdge(NewEdge(EdgeBinds, sa.ID, role.ID))

	workloads = g.GetWorkloadsUsingSA(sa.ID)
	if len(workloads) != 2 {
		t.Errorf("After adding binds edge, GetWorkloadsUsingSA() returned %d, want 2", len(workloads))
	}

	// Unknown SA returns nil/empty
	unknown := g.GetWorkloadsUsingSA("nonexistent")
	if len(unknown) != 0 {
		t.Errorf("expected 0, got %d", len(unknown))
	}
}

// ---------------------------------------------------------------------------
// builder.go tests
// ---------------------------------------------------------------------------

func TestNewBuilderAndBuild(t *testing.T) {
	b := NewBuilder()
	if b == nil {
		t.Fatal("NewBuilder() returned nil")
	}
	g := b.Build()
	if g == nil {
		t.Fatal("Build() returned nil")
	}
	// Graph() is an alias
	if b.Graph() != g {
		t.Error("Graph() and Build() should return the same instance")
	}
}

func TestBuilderAddServiceAccount(t *testing.T) {
	tests := []struct {
		name            string
		sa              *corev1.ServiceAccount
		wantCloudARN    string
		wantGCPSA       string
		wantAzureID     string
		wantAutomount   bool
		wantEKSPodIdent string
	}{
		{
			name: "basic SA",
			sa: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "test-sa",
					Namespace: "default",
				},
			},
			wantAutomount: true, // default when nil
		},
		{
			name: "SA with AWS annotation",
			sa: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "aws-sa",
					Namespace: "default",
					Annotations: map[string]string{
						"eks.amazonaws.com/role-arn": "arn:aws:iam::123:role/myrole",
					},
				},
			},
			wantCloudARN:  "arn:aws:iam::123:role/myrole",
			wantAutomount: true,
		},
		{
			name: "SA with GCP annotation",
			sa: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "gcp-sa",
					Namespace: "default",
					Annotations: map[string]string{
						"iam.gke.io/gcp-service-account": "sa@proj.iam.gserviceaccount.com",
					},
				},
			},
			wantGCPSA:     "sa@proj.iam.gserviceaccount.com",
			wantAutomount: true,
		},
		{
			name: "SA with Azure annotation",
			sa: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "azure-sa",
					Namespace: "default",
					Annotations: map[string]string{
						"azure.workload.identity/client-id": "client-id-123",
					},
				},
			},
			wantAzureID:   "client-id-123",
			wantAutomount: true,
		},
		{
			name: "SA with automount disabled",
			sa: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "no-mount-sa",
					Namespace: "default",
				},
				AutomountServiceAccountToken: boolPtr(false),
			},
			wantAutomount: false,
		},
		{
			name: "SA with EKS Pod Identity annotation",
			sa: &corev1.ServiceAccount{
				ObjectMeta: metav1.ObjectMeta{
					Name:      "eks-pi-sa",
					Namespace: "default",
					Annotations: map[string]string{
						"pods.eks.amazonaws.com/service-account-token-audience": "sts.amazonaws.com",
					},
				},
			},
			wantEKSPodIdent: "sts.amazonaws.com",
			wantAutomount:   true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			b := NewBuilder()
			if err := b.AddServiceAccount(tt.sa); err != nil {
				t.Fatalf("AddServiceAccount() error: %v", err)
			}

			node := b.graph.FindNode(NodeServiceAccount, tt.sa.Namespace, tt.sa.Name)
			if node == nil {
				t.Fatal("SA node not found")
			}
			if node.Metadata.CloudRoleARN != tt.wantCloudARN {
				t.Errorf("CloudRoleARN = %q, want %q", node.Metadata.CloudRoleARN, tt.wantCloudARN)
			}
			if node.Metadata.GCPServiceAccount != tt.wantGCPSA {
				t.Errorf("GCPServiceAccount = %q, want %q", node.Metadata.GCPServiceAccount, tt.wantGCPSA)
			}
			if node.Metadata.AzureManagedID != tt.wantAzureID {
				t.Errorf("AzureManagedID = %q, want %q", node.Metadata.AzureManagedID, tt.wantAzureID)
			}
			if node.Metadata.AutomountToken != tt.wantAutomount {
				t.Errorf("AutomountToken = %v, want %v", node.Metadata.AutomountToken, tt.wantAutomount)
			}
			if node.Metadata.EKSPodIdentityAssociation != tt.wantEKSPodIdent {
				t.Errorf("EKSPodIdentityAssociation = %q, want %q", node.Metadata.EKSPodIdentityAssociation, tt.wantEKSPodIdent)
			}

			// If EKS Pod Identity is set, check that an assumes edge and cloud_role node were created
			if tt.wantEKSPodIdent != "" {
				cloudRoleID := GenerateNodeID(NodeCloudRole, "", tt.wantEKSPodIdent)
				cr := b.graph.GetNode(cloudRoleID)
				if cr == nil {
					t.Error("expected cloud role node for EKS Pod Identity")
				}
				edges := b.graph.GetOutEdges(node.ID)
				foundAssumes := false
				for _, e := range edges {
					if e.Type == EdgeAssumes && e.To == cloudRoleID {
						foundAssumes = true
					}
				}
				if !foundAssumes {
					t.Error("expected EdgeAssumes from SA to cloud role")
				}
			}
		})
	}
}

func TestBuilderAddRole(t *testing.T) {
	b := NewBuilder()
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "pod-reader",
			Namespace: "default",
			Labels:    map[string]string{"app": "test"},
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods"},
				Verbs:     []string{"get", "list"},
			},
		},
	}

	if err := b.AddRole(role); err != nil {
		t.Fatalf("AddRole() error: %v", err)
	}

	node := b.graph.FindNode(NodeRole, "default", "pod-reader")
	if node == nil {
		t.Fatal("role node not found")
	}
	if node.Metadata.IsClusterRole {
		t.Error("IsClusterRole should be false for Role")
	}
	if len(node.Metadata.Rules) != 1 {
		t.Errorf("expected 1 rule, got %d", len(node.Metadata.Rules))
	}
	if node.Labels["app"] != "test" {
		t.Error("labels not set correctly")
	}
}

func TestBuilderAddClusterRole(t *testing.T) {
	b := NewBuilder()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "cluster-admin",
		},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"*"},
				Resources: []string{"*"},
				Verbs:     []string{"*"},
			},
		},
	}

	if err := b.AddClusterRole(cr); err != nil {
		t.Fatalf("AddClusterRole() error: %v", err)
	}

	node := b.graph.FindNode(NodeRole, "", "cluster-admin")
	if node == nil {
		t.Fatal("cluster role node not found")
	}
	if !node.Metadata.IsClusterRole {
		t.Error("IsClusterRole should be true for ClusterRole")
	}
	if node.Metadata.IsAggregated {
		t.Error("non-aggregated ClusterRole should not be marked aggregated")
	}
}

func TestBuilderAddClusterRoleAggregated(t *testing.T) {
	b := NewBuilder()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aggregated-role",
		},
		AggregationRule: &rbacv1.AggregationRule{
			ClusterRoleSelectors: []metav1.LabelSelector{
				{MatchLabels: map[string]string{"rbac.example.com/aggregate-to-admin": "true"}},
			},
		},
	}

	if err := b.AddClusterRole(cr); err != nil {
		t.Fatalf("AddClusterRole() error: %v", err)
	}

	node := b.graph.FindNode(NodeRole, "", "aggregated-role")
	if node == nil {
		t.Fatal("aggregated cluster role node not found")
	}
	if !node.Metadata.IsAggregated {
		t.Error("IsAggregated should be true")
	}
}

func TestBuilderAddRoleBinding(t *testing.T) {
	b := NewBuilder()
	// Pre-create the SA and Role nodes
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "my-sa", Namespace: "default"},
	}
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "my-role", Namespace: "default"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}},
		},
	}
	_ = b.AddServiceAccount(sa)
	_ = b.AddRole(role)

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-binding",
			Namespace: "default",
		},
		RoleRef: rbacv1.RoleRef{
			Kind: "Role",
			Name: "my-role",
		},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "my-sa", Namespace: "default"},
		},
	}

	if err := b.AddRoleBinding(rb); err != nil {
		t.Fatalf("AddRoleBinding() error: %v", err)
	}

	saNodeID := GenerateNodeID(NodeServiceAccount, "default", "my-sa")
	roleNodeID := GenerateNodeID(NodeRole, "default", "my-role")

	edges := b.graph.GetOutEdges(saNodeID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeBinds && e.To == roleNodeID {
			found = true
			if e.Metadata.BindingName != "my-binding" {
				t.Errorf("BindingName = %q, want %q", e.Metadata.BindingName, "my-binding")
			}
			if e.Metadata.IsClusterBinding {
				t.Error("IsClusterBinding should be false for RoleBinding")
			}
		}
	}
	if !found {
		t.Error("expected EdgeBinds from SA to Role")
	}
}

func TestBuilderAddRoleBindingClusterRole(t *testing.T) {
	b := NewBuilder()
	// RoleBinding referencing a ClusterRole
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "my-sa", Namespace: "default"},
	}
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "view"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	}
	_ = b.AddServiceAccount(sa)
	_ = b.AddClusterRole(cr)

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "view-binding", Namespace: "default"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "view"},
		Subjects:   []rbacv1.Subject{{Kind: "ServiceAccount", Name: "my-sa", Namespace: "default"}},
	}
	_ = b.AddRoleBinding(rb)

	// The role node ID should be cluster-scoped (no namespace) for ClusterRole
	roleNodeID := GenerateNodeID(NodeRole, "", "view")
	saNodeID := GenerateNodeID(NodeServiceAccount, "default", "my-sa")

	edges := b.graph.GetOutEdges(saNodeID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeBinds && e.To == roleNodeID {
			found = true
		}
	}
	if !found {
		t.Error("expected EdgeBinds from SA to ClusterRole")
	}
}

func TestBuilderAddRoleBindingUserAndGroup(t *testing.T) {
	b := NewBuilder()
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	}
	_ = b.AddRole(role)

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "ns"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r"},
		Subjects: []rbacv1.Subject{
			{Kind: "User", Name: "alice"},
			{Kind: "Group", Name: "developers"},
			{Kind: "InvalidKind", Name: "skip"}, // should be skipped
		},
	}
	_ = b.AddRoleBinding(rb)

	// User node should have been created
	userNode := b.graph.FindNode(NodeUser, "", "alice")
	if userNode == nil {
		t.Error("expected User node for alice")
	}

	// Group node should have been created
	groupNode := b.graph.FindNode(NodeGroup, "", "developers")
	if groupNode == nil {
		t.Error("expected Group node for developers")
	}
}

func TestBuilderAddClusterRoleBinding(t *testing.T) {
	b := NewBuilder()
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "admin-sa", Namespace: "kube-system"},
	}
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	}
	_ = b.AddServiceAccount(sa)
	_ = b.AddClusterRole(cr)

	crb := &rbacv1.ClusterRoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
		RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "admin-sa", Namespace: "kube-system"},
			{Kind: "User", Name: "admin-user"},
			{Kind: "Group", Name: "admins"},
		},
	}

	if err := b.AddClusterRoleBinding(crb); err != nil {
		t.Fatalf("AddClusterRoleBinding() error: %v", err)
	}

	saNodeID := GenerateNodeID(NodeServiceAccount, "kube-system", "admin-sa")
	roleNodeID := GenerateNodeID(NodeRole, "", "cluster-admin")

	edges := b.graph.GetOutEdges(saNodeID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeBinds && e.To == roleNodeID {
			found = true
			if !e.Metadata.IsClusterBinding {
				t.Error("IsClusterBinding should be true for ClusterRoleBinding")
			}
			if e.Metadata.BindingName != "admin-binding" {
				t.Errorf("BindingName = %q", e.Metadata.BindingName)
			}
		}
	}
	if !found {
		t.Error("expected EdgeBinds from SA to cluster role")
	}

	// Check User and Group were created
	if b.graph.FindNode(NodeUser, "", "admin-user") == nil {
		t.Error("expected User node")
	}
	if b.graph.FindNode(NodeGroup, "", "admins") == nil {
		t.Error("expected Group node")
	}
}

func TestBuilderAddDeployment(t *testing.T) {
	b := NewBuilder()
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "app-sa", Namespace: "prod"},
	}
	_ = b.AddServiceAccount(sa)

	replicas := int32(3)
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "app",
			Namespace: "prod",
			Labels:    map[string]string{"app": "myapp"},
		},
		Spec: appsv1.DeploymentSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "app-sa",
					Containers: []corev1.Container{
						{Name: "main", Image: "nginx"},
					},
				},
			},
		},
	}

	if err := b.AddDeployment(dep); err != nil {
		t.Fatalf("AddDeployment() error: %v", err)
	}

	node := b.graph.FindNode(NodeWorkload, "prod", "app")
	if node == nil {
		t.Fatal("deployment node not found")
	}
	if node.Metadata.WorkloadKind != "Deployment" {
		t.Errorf("WorkloadKind = %q", node.Metadata.WorkloadKind)
	}
	if node.Metadata.Replicas != 3 {
		t.Errorf("Replicas = %d, want 3", node.Metadata.Replicas)
	}
	if node.Labels["app"] != "myapp" {
		t.Error("labels not set")
	}

	// Check EdgeUses to SA
	saNodeID := GenerateNodeID(NodeServiceAccount, "prod", "app-sa")
	edges := b.graph.GetOutEdges(node.ID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeUses && e.To == saNodeID {
			found = true
		}
	}
	if !found {
		t.Error("expected EdgeUses from deployment to SA")
	}
}

func TestBuilderAddDeploymentDefaultSA(t *testing.T) {
	b := NewBuilder()
	// Pre-create the default SA
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"},
	})

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "dep", Namespace: "ns"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					// ServiceAccountName not set -> should default to "default"
					Containers: []corev1.Container{{Name: "c", Image: "img"}},
				},
			},
		},
	}

	if err := b.AddDeployment(dep); err != nil {
		t.Fatalf("error: %v", err)
	}

	saNodeID := GenerateNodeID(NodeServiceAccount, "ns", "default")
	wlNodeID := GenerateNodeID(NodeWorkload, "ns", "dep")
	edges := b.graph.GetOutEdges(wlNodeID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeUses && e.To == saNodeID {
			found = true
		}
	}
	if !found {
		t.Error("deployment with no SA specified should use 'default'")
	}
}

func TestBuilderBuildResourceEdges(t *testing.T) {
	b := NewBuilder()

	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-reader", Namespace: "default"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{""},
				Resources: []string{"pods", "pods/log"},
				Verbs:     []string{"get", "list"},
			},
		},
	}
	_ = b.AddRole(role)

	b.BuildResourceEdges()

	roleNodeID := GenerateNodeID(NodeRole, "default", "pod-reader")
	edges := b.graph.GetOutEdges(roleNodeID)
	if len(edges) != 2 {
		t.Fatalf("expected 2 resource edges, got %d", len(edges))
	}

	for _, e := range edges {
		if e.Type != EdgeGrants {
			t.Errorf("edge type = %q, want %q", e.Type, EdgeGrants)
		}
		if len(e.Metadata.Verbs) != 2 {
			t.Errorf("edge verbs = %v", e.Metadata.Verbs)
		}
	}

	// Check resource nodes created
	podsNode := b.graph.FindNode(NodeK8sResource, "default", "pods")
	if podsNode == nil {
		t.Error("pods resource node not created")
	} else if podsNode.Metadata.ResourceKind != "pods" {
		t.Errorf("ResourceKind = %q", podsNode.Metadata.ResourceKind)
	}
}

func TestBuilderBuildResourceEdgesIdempotent(t *testing.T) {
	b := NewBuilder()
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "ns"},
		Rules: []rbacv1.PolicyRule{
			{APIGroups: []string{""}, Resources: []string{"secrets"}, Verbs: []string{"get"}},
		},
	}
	_ = b.AddRole(role)

	b.BuildResourceEdges()
	b.BuildResourceEdges() // second call should be idempotent (duplicate edges silently succeed)

	roleNodeID := GenerateNodeID(NodeRole, "ns", "r")
	edges := b.graph.GetOutEdges(roleNodeID)
	if len(edges) != 1 {
		t.Errorf("expected 1 edge after double BuildResourceEdges, got %d", len(edges))
	}
}

func TestBuilderAddNetworkPolicy(t *testing.T) {
	b := NewBuilder()
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt32(80)
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "deny-all",
			Namespace: "default",
		},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{
				MatchLabels: map[string]string{"app": "web"},
			},
			PolicyTypes: []networkingv1.PolicyType{
				networkingv1.PolicyTypeIngress,
				networkingv1.PolicyTypeEgress,
			},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{
							PodSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"role": "frontend"},
							},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &protocol, Port: &port},
					},
				},
			},
		},
	}

	if err := b.AddNetworkPolicy(np); err != nil {
		t.Fatalf("AddNetworkPolicy() error: %v", err)
	}

	node := b.graph.FindNode(NodeNetworkPolicy, "default", "deny-all")
	if node == nil {
		t.Fatal("network policy node not found")
	}
	if node.Metadata.NetworkPolicy == nil {
		t.Fatal("NetworkPolicy metadata nil")
	}
	npInfo := node.Metadata.NetworkPolicy
	if npInfo.PodSelector["app"] != "web" {
		t.Error("PodSelector not set")
	}
	if len(npInfo.PolicyTypes) != 2 {
		t.Errorf("PolicyTypes len = %d", len(npInfo.PolicyTypes))
	}
	if len(npInfo.IngressRules) != 1 {
		t.Errorf("IngressRules len = %d", len(npInfo.IngressRules))
	}
	if npInfo.IngressRules[0].FromPodSelector["role"] != "frontend" {
		t.Error("ingress FromPodSelector not set")
	}
	if len(npInfo.IngressRules[0].Ports) != 1 {
		t.Error("ingress ports not set")
	}
	// Egress is in policy types but no rules -> deny all
	if !npInfo.DenyAllEgress {
		t.Error("expected DenyAllEgress=true when Egress policy type present but no rules")
	}
}

func TestBuilderAddNetworkPolicyDenyAllIngress(t *testing.T) {
	b := NewBuilder()
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "deny-ingress", Namespace: "ns"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			// No Ingress rules -> deny all
		},
	}
	_ = b.AddNetworkPolicy(np)

	node := b.graph.FindNode(NodeNetworkPolicy, "ns", "deny-ingress")
	if node == nil || node.Metadata.NetworkPolicy == nil {
		t.Fatal("node or metadata nil")
	}
	if !node.Metadata.NetworkPolicy.DenyAllIngress {
		t.Error("expected DenyAllIngress=true")
	}
}

func TestBuilderAddNetworkPolicyAllowAllIngress(t *testing.T) {
	b := NewBuilder()
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-all", Namespace: "ns"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{}, // empty from + empty ports = allow all
			},
		},
	}
	_ = b.AddNetworkPolicy(np)

	node := b.graph.FindNode(NodeNetworkPolicy, "ns", "allow-all")
	if !node.Metadata.NetworkPolicy.AllowAllIngress {
		t.Error("expected AllowAllIngress=true")
	}
}

func TestBuilderAddService(t *testing.T) {
	b := NewBuilder()
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "my-svc",
			Namespace: "default",
			Labels:    map[string]string{"app": "web"},
		},
		Spec: corev1.ServiceSpec{
			Type:      corev1.ServiceTypeLoadBalancer,
			ClusterIP: "10.0.0.1",
			Selector:  map[string]string{"app": "web"},
			Ports: []corev1.ServicePort{
				{
					Name:       "http",
					Port:       80,
					TargetPort: intstr.FromInt32(8080),
					NodePort:   30080,
					Protocol:   corev1.ProtocolTCP,
				},
			},
		},
	}

	if err := b.AddService(svc); err != nil {
		t.Fatalf("AddService() error: %v", err)
	}

	node := b.graph.FindNode(NodeService, "default", "my-svc")
	if node == nil {
		t.Fatal("service node not found")
	}
	si := node.Metadata.ServiceInfo
	if si == nil {
		t.Fatal("ServiceInfo nil")
	}
	if si.ServiceType != "LoadBalancer" {
		t.Errorf("ServiceType = %q", si.ServiceType)
	}
	if si.ClusterIP != "10.0.0.1" {
		t.Errorf("ClusterIP = %q", si.ClusterIP)
	}
	if len(si.Ports) != 1 {
		t.Fatalf("Ports len = %d", len(si.Ports))
	}
	if si.Ports[0].Port != 80 || si.Ports[0].NodePort != 30080 {
		t.Errorf("Port = %d, NodePort = %d", si.Ports[0].Port, si.Ports[0].NodePort)
	}
}

func TestParseWorkloadRef(t *testing.T) {
	tests := []struct {
		ref          string
		defaultNS    string
		wantKind     string
		wantNS       string
		wantName     string
	}{
		// single-part: default to Deployment
		{"myapp", "default", "Deployment", "default", "myapp"},
		// kind/name variants
		{"deployment/myapp", "default", "Deployment", "default", "myapp"},
		{"deploy/myapp", "default", "Deployment", "default", "myapp"},
		{"deployments/myapp", "default", "Deployment", "default", "myapp"},
		{"statefulset/mydb", "ns", "StatefulSet", "ns", "mydb"},
		{"sts/mydb", "ns", "StatefulSet", "ns", "mydb"},
		{"statefulsets/mydb", "ns", "StatefulSet", "ns", "mydb"},
		{"daemonset/agent", "ns", "DaemonSet", "ns", "agent"},
		{"ds/agent", "ns", "DaemonSet", "ns", "agent"},
		{"daemonsets/agent", "ns", "DaemonSet", "ns", "agent"},
		{"job/myjob", "ns", "Job", "ns", "myjob"},
		{"jobs/myjob", "ns", "Job", "ns", "myjob"},
		{"cronjob/cj", "ns", "CronJob", "ns", "cj"},
		{"cj/cj", "ns", "CronJob", "ns", "cj"},
		{"cronjobs/cj", "ns", "CronJob", "ns", "cj"},
		{"pod/mypod", "ns", "Pod", "ns", "mypod"},
		{"pods/mypod", "ns", "Pod", "ns", "mypod"},
		// 2-part with unknown kind prefix -> treated as namespace/name
		{"mynamespace/myapp", "default", "Deployment", "mynamespace", "myapp"},
		// 3-part: kind/namespace/name
		{"StatefulSet/prod/mydb", "default", "StatefulSet", "prod", "mydb"},
		// 4+ parts: fallback
		{"a/b/c/d", "default", "Deployment", "default", "a/b/c/d"},
	}

	for _, tt := range tests {
		t.Run(tt.ref, func(t *testing.T) {
			kind, ns, name := ParseWorkloadRef(tt.ref, tt.defaultNS)
			if kind != tt.wantKind {
				t.Errorf("kind = %q, want %q", kind, tt.wantKind)
			}
			if ns != tt.wantNS {
				t.Errorf("namespace = %q, want %q", ns, tt.wantNS)
			}
			if name != tt.wantName {
				t.Errorf("name = %q, want %q", name, tt.wantName)
			}
		})
	}
}

func TestBuilderAddCloudRoleEdge(t *testing.T) {
	b := NewBuilder()
	sa := &corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "ns"},
	}
	_ = b.AddServiceAccount(sa)

	err := b.AddCloudRoleEdge("ns", "sa", "aws", "arn:aws:iam::123:role/r")
	if err != nil {
		t.Fatalf("AddCloudRoleEdge() error: %v", err)
	}

	// Cloud role node should exist
	cloudID := GenerateNodeID(NodeCloudRole, "", "arn:aws:iam::123:role/r")
	cr := b.graph.GetNode(cloudID)
	if cr == nil {
		t.Fatal("cloud role node not created")
	}
	if cr.Metadata.CloudProvider != "aws" {
		t.Errorf("CloudProvider = %q", cr.Metadata.CloudProvider)
	}

	// Edge should exist
	saID := GenerateNodeID(NodeServiceAccount, "ns", "sa")
	edges := b.graph.GetOutEdges(saID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeAssumes && e.To == cloudID {
			found = true
			if e.Metadata.RoleARN != "arn:aws:iam::123:role/r" {
				t.Errorf("RoleARN = %q", e.Metadata.RoleARN)
			}
		}
	}
	if !found {
		t.Error("expected EdgeAssumes from SA to cloud role")
	}

	// Calling again should reuse existing cloud role node
	err = b.AddCloudRoleEdge("ns", "sa", "aws", "arn:aws:iam::123:role/r")
	if err != nil {
		t.Errorf("second AddCloudRoleEdge() error: %v", err)
	}
	cloudRoles := b.graph.GetNodesByType(NodeCloudRole)
	if len(cloudRoles) != 1 {
		t.Errorf("expected 1 cloud role node, got %d", len(cloudRoles))
	}
}

func TestBuilderGetWorkloadNetworkExposure(t *testing.T) {
	b := NewBuilder()

	// Create a workload
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "ns"}}
	_ = b.AddServiceAccount(sa)

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "web",
			Namespace: "ns",
			Labels:    map[string]string{"app": "web"},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "sa",
					Containers:         []corev1.Container{{Name: "c", Image: "img"}},
				},
			},
		},
	}
	_ = b.AddDeployment(dep)

	// Add a network policy that selects this workload
	protocol := corev1.ProtocolTCP
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "np", Namespace: "ns"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
			Ingress: []networkingv1.NetworkPolicyIngressRule{
				{
					From: []networkingv1.NetworkPolicyPeer{
						{PodSelector: &metav1.LabelSelector{MatchLabels: map[string]string{"role": "frontend"}}},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &protocol, Port: ptrIntStr(intstr.FromInt32(80))},
					},
				},
			},
		},
	}
	_ = b.AddNetworkPolicy(np)

	// Add a LoadBalancer service that selects this workload
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "web-svc", Namespace: "ns"},
		Spec: corev1.ServiceSpec{
			Type:     corev1.ServiceTypeLoadBalancer,
			Selector: map[string]string{"app": "web"},
			Ports: []corev1.ServicePort{
				{Port: 80, Protocol: corev1.ProtocolTCP},
			},
		},
	}
	_ = b.AddService(svc)

	wlID := GenerateNodeID(NodeWorkload, "ns", "web")
	exposure := b.GetWorkloadNetworkExposure(wlID)
	if exposure == nil {
		t.Fatal("GetWorkloadNetworkExposure() returned nil")
	}
	if exposure.WorkloadName != "web" {
		t.Errorf("WorkloadName = %q", exposure.WorkloadName)
	}
	if len(exposure.NetworkPolicies) != 1 || exposure.NetworkPolicies[0] != "np" {
		t.Errorf("NetworkPolicies = %v", exposure.NetworkPolicies)
	}
	if !exposure.HasIngressPolicy {
		t.Error("expected HasIngressPolicy=true")
	}
	if len(exposure.Services) != 1 || exposure.Services[0].Name != "web-svc" {
		t.Errorf("Services = %v", exposure.Services)
	}
	if !exposure.IsExternallyExposed {
		t.Error("expected IsExternallyExposed=true for LoadBalancer")
	}

	// Non-existent workload
	if got := b.GetWorkloadNetworkExposure("nonexistent"); got != nil {
		t.Error("expected nil for nonexistent workload")
	}
}

func TestBuilderGetWorkloadNetworkExposureNoMatch(t *testing.T) {
	b := NewBuilder()
	sa := &corev1.ServiceAccount{ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "ns"}}
	_ = b.AddServiceAccount(sa)

	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "backend",
			Namespace: "ns",
			Labels:    map[string]string{"app": "backend"},
		},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "sa",
					Containers:         []corev1.Container{{Name: "c", Image: "img"}},
				},
			},
		},
	}
	_ = b.AddDeployment(dep)

	// NP in same namespace but selects different labels
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "np", Namespace: "ns"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{MatchLabels: map[string]string{"app": "web"}},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeIngress},
		},
	}
	_ = b.AddNetworkPolicy(np)

	// Service in different namespace
	svc := &corev1.Service{
		ObjectMeta: metav1.ObjectMeta{Name: "svc", Namespace: "other-ns"},
		Spec: corev1.ServiceSpec{
			Selector: map[string]string{"app": "backend"},
			Ports:    []corev1.ServicePort{{Port: 80}},
		},
	}
	_ = b.AddService(svc)

	wlID := GenerateNodeID(NodeWorkload, "ns", "backend")
	exposure := b.GetWorkloadNetworkExposure(wlID)
	if len(exposure.NetworkPolicies) != 0 {
		t.Errorf("expected no network policies, got %v", exposure.NetworkPolicies)
	}
	if len(exposure.Services) != 0 {
		t.Errorf("expected no services, got %v", exposure.Services)
	}
}

func TestMatchLabels(t *testing.T) {
	tests := []struct {
		name      string
		workload  map[string]string
		selector  map[string]string
		want      bool
	}{
		{"empty selector matches all", map[string]string{"a": "1"}, nil, true},
		{"exact match", map[string]string{"a": "1"}, map[string]string{"a": "1"}, true},
		{"subset match", map[string]string{"a": "1", "b": "2"}, map[string]string{"a": "1"}, true},
		{"mismatch value", map[string]string{"a": "1"}, map[string]string{"a": "2"}, false},
		{"missing key", map[string]string{"a": "1"}, map[string]string{"b": "1"}, false},
		{"workload has no labels", nil, map[string]string{"a": "1"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := matchLabels(tt.workload, tt.selector); got != tt.want {
				t.Errorf("matchLabels() = %v, want %v", got, tt.want)
			}
		})
	}
}

func TestBuilderGetServiceAccountsWithCloudIdentity(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{
			Name: "aws-sa", Namespace: "ns",
			Annotations: map[string]string{"eks.amazonaws.com/role-arn": "arn"},
		},
	})
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "plain-sa", Namespace: "ns"},
	})

	result := b.GetServiceAccountsWithCloudIdentity()
	if len(result) != 1 {
		t.Errorf("expected 1 SA with cloud identity, got %d", len(result))
	}
	if result[0].Name != "aws-sa" {
		t.Errorf("expected aws-sa, got %s", result[0].Name)
	}
}

func TestBuilderAddCloudRole(t *testing.T) {
	b := NewBuilder()
	err := b.AddCloudRole("custom-id", "my-role", "arn:aws:iam::123:role/r", "aws")
	if err != nil {
		t.Fatalf("AddCloudRole() error: %v", err)
	}

	node := b.graph.GetNode("custom-id")
	if node == nil {
		t.Fatal("cloud role node not found")
	}
	if node.Metadata.CloudRoleARN != "arn:aws:iam::123:role/r" {
		t.Errorf("CloudRoleARN = %q", node.Metadata.CloudRoleARN)
	}
	if node.Metadata.CloudProvider != "aws" {
		t.Errorf("CloudProvider = %q", node.Metadata.CloudProvider)
	}
}

func TestBuilderAddCloudRoleWithPolicies(t *testing.T) {
	b := NewBuilder()
	policies := []CloudPolicy{
		{Name: "AdminAccess", ARN: "arn:aws:iam::aws:policy/AdminAccess", Type: "managed", IsAdmin: true},
		{Name: "inline-policy", Type: "inline"},
	}
	err := b.AddCloudRoleWithPolicies("id", "role", "arn", "aws", policies)
	if err != nil {
		t.Fatalf("AddCloudRoleWithPolicies() error: %v", err)
	}

	node := b.graph.GetNode("id")
	if node == nil {
		t.Fatal("node not found")
	}
	if len(node.Metadata.CloudPolicies) != 2 {
		t.Errorf("CloudPolicies len = %d", len(node.Metadata.CloudPolicies))
	}
	if len(node.Metadata.PolicyARNs) != 2 {
		t.Errorf("PolicyARNs len = %d", len(node.Metadata.PolicyARNs))
	}
	// First policy has ARN, second uses Name as fallback
	if node.Metadata.PolicyARNs[0] != "arn:aws:iam::aws:policy/AdminAccess" {
		t.Errorf("PolicyARNs[0] = %q", node.Metadata.PolicyARNs[0])
	}
	if node.Metadata.PolicyARNs[1] != "inline-policy" {
		t.Errorf("PolicyARNs[1] = %q", node.Metadata.PolicyARNs[1])
	}
}

func TestBuilderAddCloudResource(t *testing.T) {
	b := NewBuilder()
	err := b.AddCloudResource("res-id", "s3-bucket", "arn:aws:s3:::mybucket", "aws")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	node := b.graph.GetNode("res-id")
	if node == nil {
		t.Fatal("node not found")
	}
	if node.Metadata.ResourceKind != "s3-bucket" {
		t.Errorf("ResourceKind = %q", node.Metadata.ResourceKind)
	}
}

func TestBuilderAddCloudAssumeEdge(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "ns"},
	})
	_ = b.AddCloudRole("cr-id", "role", "arn", "aws")

	saID := GenerateNodeID(NodeServiceAccount, "ns", "sa")
	err := b.AddCloudAssumeEdge(saID, "cr-id")
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	edges := b.graph.GetOutEdges(saID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeAssumes && e.To == "cr-id" {
			found = true
		}
	}
	if !found {
		t.Error("expected EdgeAssumes edge")
	}
}

func TestBuilderAddCloudAllowEdge(t *testing.T) {
	b := NewBuilder()
	_ = b.AddCloudRole("cr-id", "role", "arn", "aws")
	_ = b.AddCloudResource("res-id", "s3", "arn", "aws")

	err := b.AddCloudAllowEdge("cr-id", "res-id", []string{"s3:GetObject"}, SeverityHigh)
	if err != nil {
		t.Fatalf("error: %v", err)
	}

	edges := b.graph.GetOutEdges("cr-id")
	found := false
	for _, e := range edges {
		if e.Type == EdgeAllows && e.To == "res-id" {
			found = true
			if e.Metadata.Severity != SeverityHigh {
				t.Errorf("Severity = %q", e.Metadata.Severity)
			}
		}
	}
	if !found {
		t.Error("expected EdgeAllows edge")
	}
}

func TestExtractPodSecurityContext(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "ns"},
	})

	privileged := true
	runAsUser := int64(0)
	readOnly := true
	dep := &appsv1.Deployment{
		ObjectMeta: metav1.ObjectMeta{Name: "priv-dep", Namespace: "ns"},
		Spec: appsv1.DeploymentSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "sa",
					HostNetwork:        true,
					HostPID:            true,
					HostIPC:            true,
					Volumes: []corev1.Volume{
						{Name: "host", VolumeSource: corev1.VolumeSource{
							HostPath: &corev1.HostPathVolumeSource{Path: "/var/run/docker.sock"},
						}},
					},
					Containers: []corev1.Container{
						{
							Name:  "main",
							Image: "img",
							SecurityContext: &corev1.SecurityContext{
								Privileged:             &privileged,
								RunAsUser:              &runAsUser,
								ReadOnlyRootFilesystem: &readOnly,
								Capabilities: &corev1.Capabilities{
									Add: []corev1.Capability{"NET_ADMIN", "SYS_PTRACE"},
								},
							},
							Ports: []corev1.ContainerPort{
								{HostPort: 8080},
							},
							Env: []corev1.EnvVar{
								{Name: "SECRET", ValueFrom: &corev1.EnvVarSource{
									SecretKeyRef: &corev1.SecretKeySelector{},
								}},
							},
							EnvFrom: []corev1.EnvFromSource{
								{SecretRef: &corev1.SecretEnvSource{}},
							},
						},
					},
				},
			},
		},
	}
	_ = b.AddDeployment(dep)

	node := b.graph.FindNode(NodeWorkload, "ns", "priv-dep")
	if node == nil {
		t.Fatal("node not found")
	}
	psc := node.Metadata.PodSecurityContext
	if psc == nil {
		t.Fatal("PodSecurityContext nil")
	}
	if !psc.HostNetwork {
		t.Error("expected HostNetwork=true")
	}
	if !psc.HostPID {
		t.Error("expected HostPID=true")
	}
	if !psc.HostIPC {
		t.Error("expected HostIPC=true")
	}
	if len(psc.HostPaths) != 1 || psc.HostPaths[0] != "/var/run/docker.sock" {
		t.Errorf("HostPaths = %v", psc.HostPaths)
	}
	if len(psc.Containers) != 1 {
		t.Fatalf("Containers len = %d", len(psc.Containers))
	}
	c := psc.Containers[0]
	if !c.Privileged {
		t.Error("expected Privileged=true")
	}
	if !c.RunAsRoot {
		t.Error("expected RunAsRoot=true")
	}
	if !c.ReadOnlyRootFilesystem {
		t.Error("expected ReadOnlyRootFilesystem=true")
	}
	if len(c.Capabilities) != 2 {
		t.Errorf("Capabilities = %v", c.Capabilities)
	}
	if len(c.HostPorts) != 1 || c.HostPorts[0] != 8080 {
		t.Errorf("HostPorts = %v", c.HostPorts)
	}
	if c.SecretsInEnv != 2 {
		t.Errorf("SecretsInEnv = %d, want 2", c.SecretsInEnv)
	}
	if !c.AllowPrivilegeEscalation {
		t.Error("expected AllowPrivilegeEscalation=true when AllowPrivilegeEscalation is nil")
	}
}

func TestBuilderAddStatefulSet(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "ns"},
	})

	replicas := int32(3)
	sts := &appsv1.StatefulSet{
		ObjectMeta: metav1.ObjectMeta{Name: "db", Namespace: "ns"},
		Spec: appsv1.StatefulSetSpec{
			Replicas: &replicas,
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "sa",
					Containers:         []corev1.Container{{Name: "db", Image: "pg"}},
				},
			},
		},
	}
	if err := b.AddStatefulSet(sts); err != nil {
		t.Fatalf("error: %v", err)
	}

	node := b.graph.FindNode(NodeWorkload, "ns", "db")
	if node == nil {
		t.Fatal("node not found")
	}
	if node.Metadata.WorkloadKind != "StatefulSet" {
		t.Errorf("WorkloadKind = %q", node.Metadata.WorkloadKind)
	}
	if node.Metadata.Replicas != 3 {
		t.Errorf("Replicas = %d", node.Metadata.Replicas)
	}
}

func TestBuilderAddDaemonSet(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"},
	})

	ds := &appsv1.DaemonSet{
		ObjectMeta: metav1.ObjectMeta{Name: "agent", Namespace: "ns"},
		Spec: appsv1.DaemonSetSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					Containers: []corev1.Container{{Name: "agent", Image: "img"}},
				},
			},
		},
	}
	if err := b.AddDaemonSet(ds); err != nil {
		t.Fatalf("error: %v", err)
	}

	node := b.graph.FindNode(NodeWorkload, "ns", "agent")
	if node == nil {
		t.Fatal("node not found")
	}
	if node.Metadata.WorkloadKind != "DaemonSet" {
		t.Errorf("WorkloadKind = %q", node.Metadata.WorkloadKind)
	}

	// Should default to "default" SA
	saID := GenerateNodeID(NodeServiceAccount, "ns", "default")
	edges := b.graph.GetOutEdges(node.ID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeUses && e.To == saID {
			found = true
		}
	}
	if !found {
		t.Error("expected EdgeUses to default SA")
	}
}

func TestBuilderAddJob(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "job-sa", Namespace: "ns"},
	})

	job := &batchv1.Job{
		ObjectMeta: metav1.ObjectMeta{Name: "myjob", Namespace: "ns"},
		Spec: batchv1.JobSpec{
			Template: corev1.PodTemplateSpec{
				Spec: corev1.PodSpec{
					ServiceAccountName: "job-sa",
					Containers:         []corev1.Container{{Name: "worker", Image: "img"}},
				},
			},
		},
	}
	if err := b.AddJob(job); err != nil {
		t.Fatalf("error: %v", err)
	}

	node := b.graph.FindNode(NodeWorkload, "ns", "myjob")
	if node == nil {
		t.Fatal("node not found")
	}
	if node.Metadata.WorkloadKind != "Job" {
		t.Errorf("WorkloadKind = %q", node.Metadata.WorkloadKind)
	}
}

func TestBuilderAddCronJob(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"},
	})

	cj := &batchv1.CronJob{
		ObjectMeta: metav1.ObjectMeta{Name: "backup", Namespace: "ns"},
		Spec: batchv1.CronJobSpec{
			JobTemplate: batchv1.JobTemplateSpec{
				Spec: batchv1.JobSpec{
					Template: corev1.PodTemplateSpec{
						Spec: corev1.PodSpec{
							Containers: []corev1.Container{{Name: "backup", Image: "img"}},
						},
					},
				},
			},
		},
	}
	if err := b.AddCronJob(cj); err != nil {
		t.Fatalf("error: %v", err)
	}

	node := b.graph.FindNode(NodeWorkload, "ns", "backup")
	if node == nil {
		t.Fatal("node not found")
	}
	if node.Metadata.WorkloadKind != "CronJob" {
		t.Errorf("WorkloadKind = %q", node.Metadata.WorkloadKind)
	}
}

func TestBuilderAddPod(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "default", Namespace: "ns"},
	})

	// Pod with owner references should be skipped
	ownedPod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{
			Name:      "owned",
			Namespace: "ns",
			OwnerReferences: []metav1.OwnerReference{
				{Name: "dep", Kind: "Deployment"},
			},
		},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Image: "img"}},
		},
	}
	if err := b.AddPod(ownedPod); err != nil {
		t.Fatalf("error: %v", err)
	}
	if b.graph.FindNode(NodeWorkload, "ns", "owned") != nil {
		t.Error("owned pod should be skipped")
	}

	// Standalone pod
	expSeconds := int64(3600)
	standalonePod := &corev1.Pod{
		ObjectMeta: metav1.ObjectMeta{Name: "standalone", Namespace: "ns"},
		Spec: corev1.PodSpec{
			Containers: []corev1.Container{{Name: "c", Image: "img"}},
			Volumes: []corev1.Volume{
				{
					Name: "token",
					VolumeSource: corev1.VolumeSource{
						Projected: &corev1.ProjectedVolumeSource{
							Sources: []corev1.VolumeProjection{
								{
									ServiceAccountToken: &corev1.ServiceAccountTokenProjection{
										Audience:          "api.example.com",
										ExpirationSeconds: &expSeconds,
									},
								},
							},
						},
					},
				},
			},
		},
	}
	if err := b.AddPod(standalonePod); err != nil {
		t.Fatalf("error: %v", err)
	}

	node := b.graph.FindNode(NodeWorkload, "ns", "standalone")
	if node == nil {
		t.Fatal("standalone pod node not found")
	}
	if node.Metadata.WorkloadKind != "Pod" {
		t.Errorf("WorkloadKind = %q", node.Metadata.WorkloadKind)
	}
	if node.Metadata.Replicas != 1 {
		t.Errorf("Replicas = %d, want 1", node.Metadata.Replicas)
	}
	if node.Metadata.TokenAudience != "api.example.com" {
		t.Errorf("TokenAudience = %q", node.Metadata.TokenAudience)
	}
	if node.Metadata.TokenExpirationSeconds != 3600 {
		t.Errorf("TokenExpirationSeconds = %d", node.Metadata.TokenExpirationSeconds)
	}
}

func TestBuilderResourceEdgesWithResourceNames(t *testing.T) {
	b := NewBuilder()
	role := &rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "secret-reader", Namespace: "ns"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups:     []string{""},
				Resources:     []string{"secrets"},
				ResourceNames: []string{"my-secret"},
				Verbs:         []string{"get"},
			},
		},
	}
	_ = b.AddRole(role)
	b.BuildResourceEdges()

	roleID := GenerateNodeID(NodeRole, "ns", "secret-reader")
	edges := b.graph.GetOutEdges(roleID)
	if len(edges) != 1 {
		t.Fatalf("expected 1 edge, got %d", len(edges))
	}
	if len(edges[0].Metadata.ResourceNames) != 1 || edges[0].Metadata.ResourceNames[0] != "my-secret" {
		t.Errorf("ResourceNames = %v", edges[0].Metadata.ResourceNames)
	}
}

func TestBuilderResourceEdgesClusterRoleWithApiGroup(t *testing.T) {
	b := NewBuilder()
	cr := &rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "deploy-manager"},
		Rules: []rbacv1.PolicyRule{
			{
				APIGroups: []string{"apps"},
				Resources: []string{"deployments"},
				Verbs:     []string{"get", "create", "update"},
			},
		},
	}
	_ = b.AddClusterRole(cr)
	b.BuildResourceEdges()

	// Resource node should be cluster-scoped (empty namespace for ClusterRole)
	resNode := b.graph.FindNode(NodeK8sResource, "", "deployments")
	if resNode == nil {
		t.Fatal("resource node not created")
	}
	if resNode.Labels["apiGroup"] != "apps" {
		t.Errorf("apiGroup label = %q", resNode.Labels["apiGroup"])
	}
}

func TestConvertRules(t *testing.T) {
	policyRules := []rbacv1.PolicyRule{
		{
			APIGroups:     []string{"", "apps"},
			Resources:     []string{"pods", "deployments"},
			ResourceNames: []string{"my-pod"},
			Verbs:         []string{"get", "list"},
		},
	}

	rules := convertRules(policyRules)
	if len(rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(rules))
	}
	r := rules[0]
	if len(r.APIGroups) != 2 {
		t.Errorf("APIGroups = %v", r.APIGroups)
	}
	if len(r.Resources) != 2 {
		t.Errorf("Resources = %v", r.Resources)
	}
	if len(r.ResourceNames) != 1 || r.ResourceNames[0] != "my-pod" {
		t.Errorf("ResourceNames = %v", r.ResourceNames)
	}
	if len(r.Verbs) != 2 {
		t.Errorf("Verbs = %v", r.Verbs)
	}
}

func TestBuilderAddNetworkPolicyEgressRules(t *testing.T) {
	b := NewBuilder()
	protocol := corev1.ProtocolTCP
	port := intstr.FromInt32(443)
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "egress-np", Namespace: "ns"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{
					To: []networkingv1.NetworkPolicyPeer{
						{
							NamespaceSelector: &metav1.LabelSelector{
								MatchLabels: map[string]string{"env": "prod"},
							},
							IPBlock: &networkingv1.IPBlock{CIDR: "10.0.0.0/8"},
						},
					},
					Ports: []networkingv1.NetworkPolicyPort{
						{Protocol: &protocol, Port: &port},
					},
				},
			},
		},
	}
	_ = b.AddNetworkPolicy(np)

	node := b.graph.FindNode(NodeNetworkPolicy, "ns", "egress-np")
	if node == nil {
		t.Fatal("node not found")
	}
	npInfo := node.Metadata.NetworkPolicy
	if len(npInfo.EgressRules) != 1 {
		t.Fatalf("EgressRules len = %d", len(npInfo.EgressRules))
	}
	er := npInfo.EgressRules[0]
	if er.ToNamespaceSelector["env"] != "prod" {
		t.Error("ToNamespaceSelector not set")
	}
	if er.ToIPBlock != "10.0.0.0/8" {
		t.Errorf("ToIPBlock = %q", er.ToIPBlock)
	}
	if len(er.Ports) != 1 || er.Ports[0].Port != "443" {
		t.Errorf("Ports = %v", er.Ports)
	}
}

func TestBuilderAddNetworkPolicyAllowAllEgress(t *testing.T) {
	b := NewBuilder()
	np := &networkingv1.NetworkPolicy{
		ObjectMeta: metav1.ObjectMeta{Name: "allow-egress", Namespace: "ns"},
		Spec: networkingv1.NetworkPolicySpec{
			PodSelector: metav1.LabelSelector{},
			PolicyTypes: []networkingv1.PolicyType{networkingv1.PolicyTypeEgress},
			Egress: []networkingv1.NetworkPolicyEgressRule{
				{}, // empty to + empty ports = allow all
			},
		},
	}
	_ = b.AddNetworkPolicy(np)

	node := b.graph.FindNode(NodeNetworkPolicy, "ns", "allow-egress")
	if !node.Metadata.NetworkPolicy.AllowAllEgress {
		t.Error("expected AllowAllEgress=true")
	}
}

// Test that EdgeUses properly tracks SA-to-workload mapping
func TestGraphSAToWorkloadTracking(t *testing.T) {
	g := New()
	sa := NewNode(NodeServiceAccount, "ns", "sa")
	dep1 := NewNode(NodeWorkload, "ns", "dep1")
	dep2 := NewNode(NodeWorkload, "ns", "dep2")
	_ = g.AddNode(sa)
	_ = g.AddNode(dep1)
	_ = g.AddNode(dep2)

	// Only EdgeUses should track
	_ = g.AddEdge(NewEdge(EdgeUses, dep1.ID, sa.ID))
	_ = g.AddEdge(NewEdge(EdgeUses, dep2.ID, sa.ID))
	_ = g.AddEdge(NewEdge(EdgeBinds, sa.ID, sa.ID)) // non-uses edge

	workloads := g.GetWorkloadsUsingSA(sa.ID)
	if len(workloads) != 2 {
		t.Errorf("expected 2, got %d", len(workloads))
	}
}

// Test Graph with DistroProfile
func TestGraphDistroProfile(t *testing.T) {
	g := New()
	if g.DistroProfile != nil {
		t.Error("DistroProfile should be nil initially")
	}

	g.DistroProfile = &GraphDistroProfile{
		Platform:      "EKS",
		CloudProvider: "aws",
		FeatureFlags:  map[string]bool{"irsa": true},
	}

	if g.DistroProfile.Platform != "EKS" {
		t.Errorf("Platform = %q", g.DistroProfile.Platform)
	}
}

// Test ClassifyEdgeSeverity for statefulsets and daemonsets
func TestClassifyEdgeSeverityWorkloadTypes(t *testing.T) {
	tests := []struct {
		name         string
		resourceKind string
		verbs        []string
		want         Severity
	}{
		{"statefulsets dangerous", "statefulsets", []string{"create"}, SeverityHigh},
		{"daemonsets dangerous", "daemonsets", []string{"delete"}, SeverityHigh},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			e := &Edge{Type: EdgeGrants, Metadata: EdgeMeta{Verbs: tt.verbs}}
			n := &Node{Type: NodeK8sResource, Metadata: NodeMetadata{ResourceKind: tt.resourceKind}}
			got := ClassifyEdgeSeverity(e, n)
			if got != tt.want {
				t.Errorf("got %q, want %q", got, tt.want)
			}
		})
	}
}

// Test RoleBinding with SA subject that has no explicit namespace (inherits binding NS)
func TestBuilderRoleBindingSADefaultNamespace(t *testing.T) {
	b := NewBuilder()
	_ = b.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "sa", Namespace: "myns"},
	})
	_ = b.AddRole(&rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "r", Namespace: "myns"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	})

	rb := &rbacv1.RoleBinding{
		ObjectMeta: metav1.ObjectMeta{Name: "rb", Namespace: "myns"},
		RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "r"},
		Subjects: []rbacv1.Subject{
			{Kind: "ServiceAccount", Name: "sa"}, // no namespace -> should use rb.Namespace
		},
	}
	_ = b.AddRoleBinding(rb)

	saID := GenerateNodeID(NodeServiceAccount, "myns", "sa")
	roleID := GenerateNodeID(NodeRole, "myns", "r")
	edges := b.graph.GetOutEdges(saID)
	found := false
	for _, e := range edges {
		if e.Type == EdgeBinds && e.To == roleID {
			found = true
		}
	}
	if !found {
		t.Error("expected SA to bind to role when subject has no explicit namespace")
	}
}

// Test error message content
func TestGraphAddNodeDuplicateErrorMessage(t *testing.T) {
	g := New()
	n := NewNode(NodeServiceAccount, "ns", "sa")
	_ = g.AddNode(n)

	err := g.AddNode(n)
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "already exists") {
		t.Errorf("error = %q, expected 'already exists'", err.Error())
	}
}

func TestGraphAddEdgeMissingNodeErrorMessages(t *testing.T) {
	g := New()
	n := NewNode(NodeServiceAccount, "ns", "sa")
	_ = g.AddNode(n)

	e1 := NewEdge(EdgeUses, "missing", n.ID)
	err1 := g.AddEdge(e1)
	if err1 == nil || !strings.Contains(err1.Error(), "source node") {
		t.Errorf("err1 = %v, expected source node error", err1)
	}

	e2 := NewEdge(EdgeUses, n.ID, "missing")
	err2 := g.AddEdge(e2)
	if err2 == nil || !strings.Contains(err2.Error(), "target node") {
		t.Errorf("err2 = %v, expected target node error", err2)
	}
}

// ---------------------------------------------------------------------------
// helpers
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool {
	return &b
}

func ptrIntStr(v intstr.IntOrString) *intstr.IntOrString {
	return &v
}

// Ensure batchv1 import is used
var _ = &batchv1.Job{}
