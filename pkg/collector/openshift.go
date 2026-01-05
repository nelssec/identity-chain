package collector

import (
	"context"
	"fmt"

	"github.com/nelssec/identity-chain/pkg/graph"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/apis/meta/v1/unstructured"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

type OpenShiftCollector struct {
	client        kubernetes.Interface
	dynamicClient dynamic.Interface
	options       Options
}

func NewOpenShiftCollector(opts Options) (*OpenShiftCollector, error) {
	config, err := getKubeConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create dynamic client: %w", err)
	}

	return &OpenShiftCollector{
		client:        client,
		dynamicClient: dynClient,
		options:       opts,
	}, nil
}

func (c *OpenShiftCollector) Collect(ctx context.Context, builder *graph.Builder) error {
	if err := c.collectSCCs(ctx, builder); err != nil {
		return err
	}
	return nil
}

func (c *OpenShiftCollector) collectSCCs(ctx context.Context, builder *graph.Builder) error {
	sccGVR := schema.GroupVersionResource{
		Group:    "security.openshift.io",
		Version:  "v1",
		Resource: "securitycontextconstraints",
	}

	sccs, err := c.dynamicClient.Resource(sccGVR).List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil
	}

	for _, scc := range sccs.Items {
		if err := c.addSCC(builder, &scc); err != nil {
			continue
		}
	}

	return nil
}

func (c *OpenShiftCollector) addSCC(builder *graph.Builder, scc *unstructured.Unstructured) error {
	name := scc.GetName()
	node := graph.NewNode(graph.NodeSCC, "", name)
	node.Labels = scc.GetLabels()

	sccInfo := &graph.SCCInfo{}

	if priority, found, _ := unstructured.NestedInt64(scc.Object, "priority"); found {
		sccInfo.Priority = int(priority)
	}

	if val, found, _ := unstructured.NestedBool(scc.Object, "allowPrivilegedContainer"); found {
		sccInfo.AllowPrivilegedContainer = val
	}

	if val, found, _ := unstructured.NestedBool(scc.Object, "allowHostDirVolumePlugin"); found {
		sccInfo.AllowHostDirVolumePlugin = val
	}

	if val, found, _ := unstructured.NestedBool(scc.Object, "allowHostNetwork"); found {
		sccInfo.AllowHostNetwork = val
	}

	if val, found, _ := unstructured.NestedBool(scc.Object, "allowHostPorts"); found {
		sccInfo.AllowHostPorts = val
	}

	if val, found, _ := unstructured.NestedBool(scc.Object, "allowHostPID"); found {
		sccInfo.AllowHostPID = val
	}

	if val, found, _ := unstructured.NestedBool(scc.Object, "allowHostIPC"); found {
		sccInfo.AllowHostIPC = val
	}

	if val, found, _ := unstructured.NestedBool(scc.Object, "readOnlyRootFilesystem"); found {
		sccInfo.ReadOnlyRootFilesystem = val
	}

	if caps, found, _ := unstructured.NestedStringSlice(scc.Object, "allowedCapabilities"); found {
		sccInfo.AllowedCapabilities = caps
	}

	if caps, found, _ := unstructured.NestedStringSlice(scc.Object, "defaultAddCapabilities"); found {
		sccInfo.DefaultAddCapabilities = caps
	}

	if caps, found, _ := unstructured.NestedStringSlice(scc.Object, "requiredDropCapabilities"); found {
		sccInfo.RequiredDropCapabilities = caps
	}

	if runAsUser, found, _ := unstructured.NestedMap(scc.Object, "runAsUser"); found {
		if typ, ok := runAsUser["type"].(string); ok {
			sccInfo.RunAsUserType = typ
		}
	}

	if selinux, found, _ := unstructured.NestedMap(scc.Object, "seLinuxContext"); found {
		if typ, ok := selinux["type"].(string); ok {
			sccInfo.SELinuxContextType = typ
		}
	}

	if fsGroup, found, _ := unstructured.NestedMap(scc.Object, "fsGroup"); found {
		if typ, ok := fsGroup["type"].(string); ok {
			sccInfo.FSGroupType = typ
		}
	}

	if suppGroups, found, _ := unstructured.NestedMap(scc.Object, "supplementalGroups"); found {
		if typ, ok := suppGroups["type"].(string); ok {
			sccInfo.SupplementalGroupsType = typ
		}
	}

	if vols, found, _ := unstructured.NestedStringSlice(scc.Object, "volumes"); found {
		sccInfo.Volumes = vols
	}

	if users, found, _ := unstructured.NestedStringSlice(scc.Object, "users"); found {
		sccInfo.Users = users
	}

	if groups, found, _ := unstructured.NestedStringSlice(scc.Object, "groups"); found {
		sccInfo.Groups = groups
	}

	if val, found, _ := unstructured.NestedBool(scc.Object, "allowPrivilegeEscalation"); found {
		sccInfo.AllowPrivilegeEscalation = &val
	}

	node.Metadata.SCCInfo = sccInfo

	return builder.Graph().AddNode(node)
}

func (c *OpenShiftCollector) IsOpenShift(ctx context.Context) bool {
	sccGVR := schema.GroupVersionResource{
		Group:    "security.openshift.io",
		Version:  "v1",
		Resource: "securitycontextconstraints",
	}

	_, err := c.dynamicClient.Resource(sccGVR).List(ctx, metav1.ListOptions{Limit: 1})
	return err == nil
}

func IsOpenShiftCluster(ctx context.Context, opts Options) bool {
	config, err := getKubeConfig(opts)
	if err != nil {
		return false
	}

	dynClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return false
	}

	sccGVR := schema.GroupVersionResource{
		Group:    "security.openshift.io",
		Version:  "v1",
		Resource: "securitycontextconstraints",
	}

	_, err = dynClient.Resource(sccGVR).List(ctx, metav1.ListOptions{Limit: 1})
	return err == nil
}
