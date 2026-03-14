package collector

import (
	"context"
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/runtime/schema"
	dynamicfake "k8s.io/client-go/dynamic/fake"
	"k8s.io/client-go/kubernetes/fake"
)

var sccGVR = schema.GroupVersionResource{
	Group:    "security.openshift.io",
	Version:  "v1",
	Resource: "securitycontextconstraints",
}

// newSCCDynamicClient creates a fake dynamic client with the SCC GVR registered
// and the given unstructured SCC objects pre-loaded via Create calls.
func newSCCDynamicClient(sccs ...*unstructured.Unstructured) *dynamicfake.FakeDynamicClient {
	scheme := runtime.NewScheme()

	dynClient := dynamicfake.NewSimpleDynamicClientWithCustomListKinds(
		scheme,
		map[schema.GroupVersionResource]string{
			sccGVR: "SecurityContextConstraintsList",
		},
	)

	// The fake dynamic client constructor does not reliably seed unstructured
	// objects, so we create them explicitly via the tracker.
	ctx := context.Background()
	for _, scc := range sccs {
		_, _ = dynClient.Resource(sccGVR).Create(ctx, scc, metav1.CreateOptions{})
	}

	return dynClient
}

func makeSCC(name string, fields map[string]interface{}) *unstructured.Unstructured {
	obj := map[string]interface{}{
		"apiVersion": "security.openshift.io/v1",
		"kind":       "SecurityContextConstraints",
		"metadata": map[string]interface{}{
			"name": name,
		},
	}
	for k, v := range fields {
		obj[k] = v
	}
	return &unstructured.Unstructured{Object: obj}
}

func TestOpenShiftCollectorImplementsCollector(t *testing.T) {
	var _ Collector = (*OpenShiftCollector)(nil)
}

func TestIsOpenShift_WithSCCs(t *testing.T) {
	dynClient := newSCCDynamicClient(makeSCC("restricted", nil))

	c := &OpenShiftCollector{
		client:        fake.NewSimpleClientset(),
		dynamicClient: dynClient,
		options:       Options{},
	}

	if !c.IsOpenShift(context.Background()) {
		t.Error("expected IsOpenShift to return true when SCCs are present")
	}
}

func TestIsOpenShift_EmptyCluster(t *testing.T) {
	// GVR is registered but no SCC objects exist.
	dynClient := newSCCDynamicClient()

	c := &OpenShiftCollector{
		client:        fake.NewSimpleClientset(),
		dynamicClient: dynClient,
		options:       Options{},
	}

	// The SCC API is available (List succeeds with empty result), so IsOpenShift
	// returns true. This matches real OpenShift behaviour where the API exists
	// even if no custom SCCs are defined.
	if !c.IsOpenShift(context.Background()) {
		t.Error("expected IsOpenShift to return true when SCC API is available")
	}
}

func TestOpenShiftCollector_CollectSCCs(t *testing.T) {
	scc1 := makeSCC("restricted", map[string]interface{}{
		"allowPrivilegedContainer": false,
		"allowHostNetwork":         false,
		"runAsUser": map[string]interface{}{
			"type": "MustRunAsRange",
		},
		"seLinuxContext": map[string]interface{}{
			"type": "MustRunAs",
		},
		"volumes": []interface{}{"configMap", "downwardAPI", "emptyDir", "persistentVolumeClaim", "projected", "secret"},
	})

	scc2 := makeSCC("privileged", map[string]interface{}{
		"allowPrivilegedContainer": true,
		"allowHostNetwork":         true,
		"allowHostPorts":           true,
		"allowHostPID":             true,
		"allowHostIPC":             true,
		"runAsUser": map[string]interface{}{
			"type": "RunAsAny",
		},
		"seLinuxContext": map[string]interface{}{
			"type": "RunAsAny",
		},
		"volumes":  []interface{}{"*"},
		"users":    []interface{}{"system:admin"},
		"groups":   []interface{}{"system:cluster-admins"},
		"priority": int64(10),
	})

	dynClient := newSCCDynamicClient(scc1, scc2)

	c := &OpenShiftCollector{
		client:        fake.NewSimpleClientset(),
		dynamicClient: dynClient,
		options:       Options{},
	}

	builder := graph.NewBuilder()
	err := c.Collect(context.Background(), builder)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	g := builder.Build()
	sccNodes := g.GetNodesByType(graph.NodeSCC)
	if len(sccNodes) != 2 {
		t.Fatalf("expected 2 SCC nodes, got %d", len(sccNodes))
	}

	// Verify restricted SCC
	restricted := g.FindNode(graph.NodeSCC, "", "restricted")
	if restricted == nil {
		t.Fatal("expected to find 'restricted' SCC node")
	}
	if restricted.Metadata.SCCInfo == nil {
		t.Fatal("expected SCCInfo to be populated for restricted SCC")
	}
	if restricted.Metadata.SCCInfo.AllowPrivilegedContainer {
		t.Error("restricted SCC should not allow privileged containers")
	}
	if restricted.Metadata.SCCInfo.RunAsUserType != "MustRunAsRange" {
		t.Errorf("expected RunAsUserType 'MustRunAsRange', got %q", restricted.Metadata.SCCInfo.RunAsUserType)
	}

	// Verify privileged SCC
	privileged := g.FindNode(graph.NodeSCC, "", "privileged")
	if privileged == nil {
		t.Fatal("expected to find 'privileged' SCC node")
	}
	if privileged.Metadata.SCCInfo == nil {
		t.Fatal("expected SCCInfo to be populated for privileged SCC")
	}
	if !privileged.Metadata.SCCInfo.AllowPrivilegedContainer {
		t.Error("privileged SCC should allow privileged containers")
	}
	if !privileged.Metadata.SCCInfo.AllowHostNetwork {
		t.Error("privileged SCC should allow host network")
	}
	if !privileged.Metadata.SCCInfo.AllowHostPorts {
		t.Error("privileged SCC should allow host ports")
	}
	if !privileged.Metadata.SCCInfo.AllowHostPID {
		t.Error("privileged SCC should allow host PID")
	}
	if !privileged.Metadata.SCCInfo.AllowHostIPC {
		t.Error("privileged SCC should allow host IPC")
	}
	if privileged.Metadata.SCCInfo.Priority != 10 {
		t.Errorf("expected priority 10, got %d", privileged.Metadata.SCCInfo.Priority)
	}
	if privileged.Metadata.SCCInfo.RunAsUserType != "RunAsAny" {
		t.Errorf("expected RunAsUserType 'RunAsAny', got %q", privileged.Metadata.SCCInfo.RunAsUserType)
	}
	if len(privileged.Metadata.SCCInfo.Users) != 1 || privileged.Metadata.SCCInfo.Users[0] != "system:admin" {
		t.Errorf("expected users [system:admin], got %v", privileged.Metadata.SCCInfo.Users)
	}
	if len(privileged.Metadata.SCCInfo.Groups) != 1 || privileged.Metadata.SCCInfo.Groups[0] != "system:cluster-admins" {
		t.Errorf("expected groups [system:cluster-admins], got %v", privileged.Metadata.SCCInfo.Groups)
	}
}

func TestOpenShiftCollector_CollectSCCs_EmptyList(t *testing.T) {
	dynClient := newSCCDynamicClient() // GVR registered, no objects

	c := &OpenShiftCollector{
		client:        fake.NewSimpleClientset(),
		dynamicClient: dynClient,
		options:       Options{},
	}

	builder := graph.NewBuilder()
	err := c.Collect(context.Background(), builder)
	if err != nil {
		t.Fatalf("Collect should not return error with empty SCC list, got: %v", err)
	}

	g := builder.Build()
	sccNodes := g.GetNodesByType(graph.NodeSCC)
	if len(sccNodes) != 0 {
		t.Errorf("expected 0 SCC nodes with empty list, got %d", len(sccNodes))
	}
}

func TestOpenShiftCollector_AddSCC_WithCapabilities(t *testing.T) {
	scc := makeSCC("custom-scc", map[string]interface{}{
		"allowedCapabilities":      []interface{}{"NET_ADMIN", "SYS_PTRACE"},
		"defaultAddCapabilities":   []interface{}{"NET_BIND_SERVICE"},
		"requiredDropCapabilities": []interface{}{"ALL"},
		"readOnlyRootFilesystem":   true,
		"fsGroup": map[string]interface{}{
			"type": "MustRunAs",
		},
		"supplementalGroups": map[string]interface{}{
			"type": "RunAsAny",
		},
	})
	// Add labels to the SCC metadata
	scc.Object["metadata"] = map[string]interface{}{
		"name":   "custom-scc",
		"labels": map[string]interface{}{"tier": "security"},
	}

	dynClient := newSCCDynamicClient(scc)

	c := &OpenShiftCollector{
		client:        fake.NewSimpleClientset(),
		dynamicClient: dynClient,
		options:       Options{},
	}

	builder := graph.NewBuilder()
	err := c.Collect(context.Background(), builder)
	if err != nil {
		t.Fatalf("Collect returned error: %v", err)
	}

	g := builder.Build()
	node := g.FindNode(graph.NodeSCC, "", "custom-scc")
	if node == nil {
		t.Fatal("expected to find custom-scc node")
	}

	info := node.Metadata.SCCInfo
	if info == nil {
		t.Fatal("expected SCCInfo to be set")
	}

	if node.Labels == nil || node.Labels["tier"] != "security" {
		t.Errorf("expected label tier=security, got %v", node.Labels)
	}

	if len(info.AllowedCapabilities) != 2 {
		t.Errorf("expected 2 allowed capabilities, got %d", len(info.AllowedCapabilities))
	}
	if len(info.DefaultAddCapabilities) != 1 || info.DefaultAddCapabilities[0] != "NET_BIND_SERVICE" {
		t.Errorf("expected default add cap [NET_BIND_SERVICE], got %v", info.DefaultAddCapabilities)
	}
	if len(info.RequiredDropCapabilities) != 1 || info.RequiredDropCapabilities[0] != "ALL" {
		t.Errorf("expected required drop cap [ALL], got %v", info.RequiredDropCapabilities)
	}
	if !info.ReadOnlyRootFilesystem {
		t.Error("expected ReadOnlyRootFilesystem to be true")
	}
	if info.FSGroupType != "MustRunAs" {
		t.Errorf("expected FSGroupType 'MustRunAs', got %q", info.FSGroupType)
	}
	if info.SupplementalGroupsType != "RunAsAny" {
		t.Errorf("expected SupplementalGroupsType 'RunAsAny', got %q", info.SupplementalGroupsType)
	}
}

func TestIsOpenShiftCluster_NoKubeConfig(t *testing.T) {
	opts := Options{KubeConfigPath: "/nonexistent/kubeconfig"}
	result := IsOpenShiftCluster(context.Background(), opts)
	if result {
		t.Error("expected IsOpenShiftCluster to return false with invalid kubeconfig")
	}
}

func TestAddSCC_AllowPrivilegeEscalation(t *testing.T) {
	scc := makeSCC("no-escalation", map[string]interface{}{
		"allowPrivilegeEscalation": false,
	})

	dynClient := newSCCDynamicClient(scc)

	c := &OpenShiftCollector{
		client:        fake.NewSimpleClientset(),
		dynamicClient: dynClient,
		options:       Options{},
	}

	builder := graph.NewBuilder()
	_ = c.Collect(context.Background(), builder)

	node := builder.Build().FindNode(graph.NodeSCC, "", "no-escalation")
	if node == nil {
		t.Fatal("expected to find no-escalation SCC")
	}
	if node.Metadata.SCCInfo.AllowPrivilegeEscalation == nil {
		t.Fatal("expected AllowPrivilegeEscalation to be set")
	}
	if *node.Metadata.SCCInfo.AllowPrivilegeEscalation != false {
		t.Error("expected AllowPrivilegeEscalation to be false")
	}
}
