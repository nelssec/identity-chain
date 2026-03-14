package collector

import (
	"context"
	"testing"

	"github.com/nelssec/identity-chain/pkg/collector/distro"
	"github.com/nelssec/identity-chain/pkg/graph"
	appsv1 "k8s.io/api/apps/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes/fake"
)

// newTestCollector creates a KubernetesCollector with a fake client and given options.
func newTestCollector(client *fake.Clientset, opts Options) *KubernetesCollector {
	profile := distro.DistroProfile{
		Platform:     "vanilla",
		FeatureFlags: map[string]bool{},
	}
	return &KubernetesCollector{
		client:        client,
		options:       opts,
		DistroProfile: &profile,
	}
}

func TestGetNamespaces_SingleNamespace(t *testing.T) {
	client := fake.NewSimpleClientset()
	opts := Options{
		Namespace:     "production",
		AllNamespaces: false,
	}
	c := newTestCollector(client, opts)

	namespaces, err := c.getNamespaces(context.Background())
	if err != nil {
		t.Fatalf("getNamespaces returned error: %v", err)
	}

	if len(namespaces) != 1 || namespaces[0] != "production" {
		t.Errorf("expected [production], got %v", namespaces)
	}
}

func TestGetNamespaces_AllNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "production"}},
	)
	opts := Options{AllNamespaces: true}
	c := newTestCollector(client, opts)

	namespaces, err := c.getNamespaces(context.Background())
	if err != nil {
		t.Fatalf("getNamespaces returned error: %v", err)
	}

	if len(namespaces) != 3 {
		t.Errorf("expected 3 namespaces, got %d: %v", len(namespaces), namespaces)
	}

	nsSet := map[string]bool{}
	for _, ns := range namespaces {
		nsSet[ns] = true
	}
	for _, expected := range []string{"default", "kube-system", "production"} {
		if !nsSet[expected] {
			t.Errorf("expected namespace %q in results", expected)
		}
	}
}

func TestCollectServiceAccounts(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "my-sa",
				Namespace: "default",
				Labels:    map[string]string{"app": "test"},
			},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "cloud-sa",
				Namespace: "default",
				Annotations: map[string]string{
					"eks.amazonaws.com/role-arn": "arn:aws:iam::123456:role/my-role",
				},
			},
		},
	)
	opts := Options{Namespace: "default"}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()
	err := c.collectServiceAccounts(context.Background(), builder, "default")
	if err != nil {
		t.Fatalf("collectServiceAccounts returned error: %v", err)
	}

	g := builder.Build()
	saNodes := g.GetNodesByType(graph.NodeServiceAccount)
	if len(saNodes) != 2 {
		t.Fatalf("expected 2 service account nodes, got %d", len(saNodes))
	}

	// Verify cloud SA has the ARN populated
	cloudSA := g.FindNode(graph.NodeServiceAccount, "default", "cloud-sa")
	if cloudSA == nil {
		t.Fatal("expected to find cloud-sa node")
	}
	if cloudSA.Metadata.CloudRoleARN != "arn:aws:iam::123456:role/my-role" {
		t.Errorf("expected cloud role ARN, got %q", cloudSA.Metadata.CloudRoleARN)
	}
}

func TestCollectRoles(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "pod-reader",
				Namespace: "default",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{""},
					Resources: []string{"pods"},
					Verbs:     []string{"get", "list", "watch"},
				},
			},
		},
	)
	opts := Options{Namespace: "default"}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()
	err := c.collectRoles(context.Background(), builder, "default")
	if err != nil {
		t.Fatalf("collectRoles returned error: %v", err)
	}

	g := builder.Build()
	roleNode := g.FindNode(graph.NodeRole, "default", "pod-reader")
	if roleNode == nil {
		t.Fatal("expected to find pod-reader role node")
	}
	if roleNode.Metadata.IsClusterRole {
		t.Error("expected role not to be a cluster role")
	}
	if len(roleNode.Metadata.Rules) != 1 {
		t.Fatalf("expected 1 rule, got %d", len(roleNode.Metadata.Rules))
	}
	if roleNode.Metadata.Rules[0].Resources[0] != "pods" {
		t.Errorf("expected resource 'pods', got %q", roleNode.Metadata.Rules[0].Resources[0])
	}
}

func TestCollectClusterRoles(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRole{
			ObjectMeta: metav1.ObjectMeta{
				Name: "cluster-admin-custom",
			},
			Rules: []rbacv1.PolicyRule{
				{
					APIGroups: []string{"*"},
					Resources: []string{"*"},
					Verbs:     []string{"*"},
				},
			},
		},
	)
	opts := Options{}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()
	err := c.collectClusterRoles(context.Background(), builder)
	if err != nil {
		t.Fatalf("collectClusterRoles returned error: %v", err)
	}

	g := builder.Build()
	crNode := g.FindNode(graph.NodeRole, "", "cluster-admin-custom")
	if crNode == nil {
		t.Fatal("expected to find cluster-admin-custom node")
	}
	if !crNode.Metadata.IsClusterRole {
		t.Error("expected cluster role to be marked as cluster role")
	}
}

func TestCollectRoleBindings(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "read-pods-binding",
				Namespace: "default",
			},
			RoleRef: rbacv1.RoleRef{
				Kind: "Role",
				Name: "pod-reader",
			},
			Subjects: []rbacv1.Subject{
				{
					Kind:      "ServiceAccount",
					Name:      "my-sa",
					Namespace: "default",
				},
			},
		},
	)
	opts := Options{Namespace: "default"}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()

	// Pre-add the SA and Role nodes so edges can be created
	_ = builder.AddServiceAccount(&corev1.ServiceAccount{
		ObjectMeta: metav1.ObjectMeta{Name: "my-sa", Namespace: "default"},
	})
	_ = builder.AddRole(&rbacv1.Role{
		ObjectMeta: metav1.ObjectMeta{Name: "pod-reader", Namespace: "default"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{""}, Resources: []string{"pods"}, Verbs: []string{"get"}}},
	})

	err := c.collectRoleBindings(context.Background(), builder, "default")
	if err != nil {
		t.Fatalf("collectRoleBindings returned error: %v", err)
	}

	g := builder.Build()
	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "default", "my-sa")
	edges := g.GetOutEdges(saID)
	if len(edges) == 0 {
		t.Error("expected at least one edge from service account to role")
	}

	foundBind := false
	for _, e := range edges {
		if e.Type == graph.EdgeBinds {
			foundBind = true
			if e.Metadata.BindingName != "read-pods-binding" {
				t.Errorf("expected binding name 'read-pods-binding', got %q", e.Metadata.BindingName)
			}
		}
	}
	if !foundBind {
		t.Error("expected a binds edge")
	}
}

func TestCollectDeployments(t *testing.T) {
	replicas := int32(3)
	client := fake.NewSimpleClientset(
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{
				Name:      "web-app",
				Namespace: "default",
				Labels:    map[string]string{"app": "web"},
			},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						ServiceAccountName: "web-sa",
						Containers: []corev1.Container{
							{Name: "web", Image: "nginx:latest"},
						},
					},
				},
			},
		},
	)
	opts := Options{Namespace: "default"}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()
	err := c.collectDeployments(context.Background(), builder, "default")
	if err != nil {
		t.Fatalf("collectDeployments returned error: %v", err)
	}

	g := builder.Build()
	workloads := g.GetNodesByType(graph.NodeWorkload)
	if len(workloads) != 1 {
		t.Fatalf("expected 1 workload node, got %d", len(workloads))
	}

	w := workloads[0]
	if w.Name != "web-app" {
		t.Errorf("expected workload name 'web-app', got %q", w.Name)
	}
	if w.Metadata.WorkloadKind != "Deployment" {
		t.Errorf("expected workload kind 'Deployment', got %q", w.Metadata.WorkloadKind)
	}
	if w.Metadata.Replicas != 3 {
		t.Errorf("expected 3 replicas, got %d", w.Metadata.Replicas)
	}
}

func TestCollect_EndToEnd(t *testing.T) {
	replicas := int32(1)
	client := fake.NewSimpleClientset(
		// Namespaces
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},

		// ServiceAccount
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "app-sa", Namespace: "default"},
		},

		// Role
		&rbacv1.Role{
			ObjectMeta: metav1.ObjectMeta{Name: "app-role", Namespace: "default"},
			Rules: []rbacv1.PolicyRule{
				{APIGroups: []string{""}, Resources: []string{"configmaps"}, Verbs: []string{"get", "list"}},
			},
		},

		// RoleBinding
		&rbacv1.RoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "app-binding", Namespace: "default"},
			RoleRef:    rbacv1.RoleRef{Kind: "Role", Name: "app-role"},
			Subjects: []rbacv1.Subject{
				{Kind: "ServiceAccount", Name: "app-sa", Namespace: "default"},
			},
		},

		// Deployment
		&appsv1.Deployment{
			ObjectMeta: metav1.ObjectMeta{Name: "app-deploy", Namespace: "default"},
			Spec: appsv1.DeploymentSpec{
				Replicas: &replicas,
				Template: corev1.PodTemplateSpec{
					Spec: corev1.PodSpec{
						ServiceAccountName: "app-sa",
						Containers:         []corev1.Container{{Name: "app", Image: "app:v1"}},
					},
				},
			},
		},
	)

	opts := Options{AllNamespaces: true, IncludeSystem: false}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()
	err := c.Collect(context.Background(), builder)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	g := builder.Build()

	// Verify service account was collected (only from "default", kube-system excluded)
	saNode := g.FindNode(graph.NodeServiceAccount, "default", "app-sa")
	if saNode == nil {
		t.Error("expected to find app-sa service account node")
	}

	// Verify deployment was collected
	workloads := g.GetNodesByType(graph.NodeWorkload)
	if len(workloads) == 0 {
		t.Error("expected at least one workload node")
	}

	// Verify role was collected
	roleNode := g.FindNode(graph.NodeRole, "default", "app-role")
	if roleNode == nil {
		t.Error("expected to find app-role node")
	}

	// Verify edges exist (SA -> Role binding)
	saID := graph.GenerateNodeID(graph.NodeServiceAccount, "default", "app-sa")
	outEdges := g.GetOutEdges(saID)
	hasBindsEdge := false
	for _, e := range outEdges {
		if e.Type == graph.EdgeBinds {
			hasBindsEdge = true
		}
	}
	if !hasBindsEdge {
		t.Error("expected a binds edge from app-sa")
	}
}

func TestCollect_ExcludesSystemNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "system-sa", Namespace: "kube-system"},
		},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "user-sa", Namespace: "default"},
		},
	)

	opts := Options{AllNamespaces: true, IncludeSystem: false}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()
	err := c.Collect(context.Background(), builder)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	g := builder.Build()

	// system-sa in kube-system should NOT be collected
	systemSA := g.FindNode(graph.NodeServiceAccount, "kube-system", "system-sa")
	if systemSA != nil {
		t.Error("expected system namespace SA to be excluded")
	}

	// user-sa in default should be collected
	userSA := g.FindNode(graph.NodeServiceAccount, "default", "user-sa")
	if userSA == nil {
		t.Error("expected user namespace SA to be included")
	}
}

func TestCollect_IncludesSystemNamespaces(t *testing.T) {
	client := fake.NewSimpleClientset(
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "default"}},
		&corev1.Namespace{ObjectMeta: metav1.ObjectMeta{Name: "kube-system"}},
		&corev1.ServiceAccount{
			ObjectMeta: metav1.ObjectMeta{Name: "system-sa", Namespace: "kube-system"},
		},
	)

	opts := Options{AllNamespaces: true, IncludeSystem: true}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()
	err := c.Collect(context.Background(), builder)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	g := builder.Build()

	systemSA := g.FindNode(graph.NodeServiceAccount, "kube-system", "system-sa")
	if systemSA == nil {
		t.Error("expected system namespace SA to be included when IncludeSystem is true")
	}
}

func TestKubernetesCollectorImplementsCollector(t *testing.T) {
	// Compile-time interface check
	var _ Collector = (*KubernetesCollector)(nil)
}

func TestCollectClusterRoleBindings(t *testing.T) {
	client := fake.NewSimpleClientset(
		&rbacv1.ClusterRoleBinding{
			ObjectMeta: metav1.ObjectMeta{Name: "admin-binding"},
			RoleRef:    rbacv1.RoleRef{Kind: "ClusterRole", Name: "cluster-admin"},
			Subjects: []rbacv1.Subject{
				{Kind: "User", Name: "admin-user"},
			},
		},
	)
	opts := Options{}
	c := newTestCollector(client, opts)

	builder := graph.NewBuilder()

	// Pre-add the ClusterRole so the edge target exists
	_ = builder.AddClusterRole(&rbacv1.ClusterRole{
		ObjectMeta: metav1.ObjectMeta{Name: "cluster-admin"},
		Rules:      []rbacv1.PolicyRule{{APIGroups: []string{"*"}, Resources: []string{"*"}, Verbs: []string{"*"}}},
	})

	err := c.collectClusterRoleBindings(context.Background(), builder)
	if err != nil {
		t.Fatalf("collectClusterRoleBindings returned error: %v", err)
	}

	g := builder.Build()

	// The User node should have been created
	userNode := g.FindNode(graph.NodeUser, "", "admin-user")
	if userNode == nil {
		t.Error("expected to find admin-user node")
	}

	// Check edge from user to cluster role
	if userNode != nil {
		edges := g.GetOutEdges(userNode.ID)
		foundBind := false
		for _, e := range edges {
			if e.Type == graph.EdgeBinds && e.Metadata.IsClusterBinding {
				foundBind = true
			}
		}
		if !foundBind {
			t.Error("expected a cluster binds edge from admin-user")
		}
	}
}
