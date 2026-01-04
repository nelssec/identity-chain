package collector

import (
	"context"
	"fmt"
	"os"
	"path/filepath"

	"github.com/nelssec/identity-chain/pkg/graph"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/clientcmd"
)

type KubernetesCollector struct {
	client  kubernetes.Interface
	options Options
}

func NewKubernetesCollector(opts Options) (*KubernetesCollector, error) {
	config, err := getKubeConfig(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to get kubernetes config: %w", err)
	}

	client, err := kubernetes.NewForConfig(config)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	return &KubernetesCollector{
		client:  client,
		options: opts,
	}, nil
}

func getKubeConfig(opts Options) (*rest.Config, error) {
	if opts.KubeConfigPath != "" {
		return clientcmd.BuildConfigFromFlags("", opts.KubeConfigPath)
	}

	if kubeconfig := os.Getenv("KUBECONFIG"); kubeconfig != "" {
		return clientcmd.BuildConfigFromFlags("", kubeconfig)
	}

	if config, err := rest.InClusterConfig(); err == nil {
		return config, nil
	}

	homeDir, err := os.UserHomeDir()
	if err != nil {
		return nil, err
	}
	kubeconfigPath := filepath.Join(homeDir, ".kube", "config")

	loadingRules := &clientcmd.ClientConfigLoadingRules{ExplicitPath: kubeconfigPath}
	configOverrides := &clientcmd.ConfigOverrides{}

	if opts.KubeContext != "" {
		configOverrides.CurrentContext = opts.KubeContext
	}

	return clientcmd.NewNonInteractiveDeferredLoadingClientConfig(loadingRules, configOverrides).ClientConfig()
}

func (c *KubernetesCollector) Collect(ctx context.Context, builder *graph.Builder) error {
	if err := c.collectClusterRoles(ctx, builder); err != nil {
		return fmt.Errorf("collecting cluster roles: %w", err)
	}

	if err := c.collectClusterRoleBindings(ctx, builder); err != nil {
		return fmt.Errorf("collecting cluster role bindings: %w", err)
	}

	namespaces, err := c.getNamespaces(ctx)
	if err != nil {
		return fmt.Errorf("getting namespaces: %w", err)
	}

	for _, ns := range namespaces {
		if !c.options.ShouldIncludeNamespace(ns) {
			continue
		}

		if err := c.collectNamespacedResources(ctx, builder, ns); err != nil {
			return fmt.Errorf("collecting resources in namespace %s: %w", ns, err)
		}
	}

	builder.BuildResourceEdges()

	c.buildCloudRoleEdges(builder)

	return nil
}

func (c *KubernetesCollector) getNamespaces(ctx context.Context) ([]string, error) {
	if !c.options.AllNamespaces {
		return []string{c.options.Namespace}, nil
	}

	nsList, err := c.client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return nil, err
	}

	namespaces := make([]string, 0, len(nsList.Items))
	for _, ns := range nsList.Items {
		namespaces = append(namespaces, ns.Name)
	}
	return namespaces, nil
}

func (c *KubernetesCollector) collectClusterRoles(ctx context.Context, builder *graph.Builder) error {
	roles, err := c.client.RbacV1().ClusterRoles().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range roles.Items {
		if err := builder.AddClusterRole(&roles.Items[i]); err != nil {
			continue
		}
	}
	return nil
}

func (c *KubernetesCollector) collectClusterRoleBindings(ctx context.Context, builder *graph.Builder) error {
	bindings, err := c.client.RbacV1().ClusterRoleBindings().List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range bindings.Items {
		if err := builder.AddClusterRoleBinding(&bindings.Items[i]); err != nil {
			continue
		}
	}
	return nil
}

func (c *KubernetesCollector) collectNamespacedResources(ctx context.Context, builder *graph.Builder, namespace string) error {
	if err := c.collectServiceAccounts(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectRoles(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectRoleBindings(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectWorkloads(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectNetworkPolicies(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectServices(ctx, builder, namespace); err != nil {
		return err
	}

	return nil
}

func (c *KubernetesCollector) collectServiceAccounts(ctx context.Context, builder *graph.Builder, namespace string) error {
	sas, err := c.client.CoreV1().ServiceAccounts(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range sas.Items {
		if err := builder.AddServiceAccount(&sas.Items[i]); err != nil {
			continue
		}
	}
	return nil
}

func (c *KubernetesCollector) collectRoles(ctx context.Context, builder *graph.Builder, namespace string) error {
	roles, err := c.client.RbacV1().Roles(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range roles.Items {
		if err := builder.AddRole(&roles.Items[i]); err != nil {
			continue
		}
	}
	return nil
}

func (c *KubernetesCollector) collectRoleBindings(ctx context.Context, builder *graph.Builder, namespace string) error {
	bindings, err := c.client.RbacV1().RoleBindings(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range bindings.Items {
		if err := builder.AddRoleBinding(&bindings.Items[i]); err != nil {
			continue
		}
	}
	return nil
}

func (c *KubernetesCollector) collectWorkloads(ctx context.Context, builder *graph.Builder, namespace string) error {
	if err := c.collectDeployments(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectStatefulSets(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectDaemonSets(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectJobs(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectCronJobs(ctx, builder, namespace); err != nil {
		return err
	}

	if err := c.collectPods(ctx, builder, namespace); err != nil {
		return err
	}

	return nil
}

func (c *KubernetesCollector) collectDeployments(ctx context.Context, builder *graph.Builder, namespace string) error {
	deps, err := c.client.AppsV1().Deployments(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range deps.Items {
		_ = builder.AddDeployment(&deps.Items[i])
	}
	return nil
}

func (c *KubernetesCollector) collectStatefulSets(ctx context.Context, builder *graph.Builder, namespace string) error {
	stss, err := c.client.AppsV1().StatefulSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range stss.Items {
		_ = builder.AddStatefulSet(&stss.Items[i])
	}
	return nil
}

func (c *KubernetesCollector) collectDaemonSets(ctx context.Context, builder *graph.Builder, namespace string) error {
	dss, err := c.client.AppsV1().DaemonSets(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range dss.Items {
		_ = builder.AddDaemonSet(&dss.Items[i])
	}
	return nil
}

func (c *KubernetesCollector) collectJobs(ctx context.Context, builder *graph.Builder, namespace string) error {
	jobs, err := c.client.BatchV1().Jobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range jobs.Items {
		_ = builder.AddJob(&jobs.Items[i])
	}
	return nil
}

func (c *KubernetesCollector) collectCronJobs(ctx context.Context, builder *graph.Builder, namespace string) error {
	cjs, err := c.client.BatchV1().CronJobs(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range cjs.Items {
		_ = builder.AddCronJob(&cjs.Items[i])
	}
	return nil
}

func (c *KubernetesCollector) collectPods(ctx context.Context, builder *graph.Builder, namespace string) error {
	pods, err := c.client.CoreV1().Pods(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range pods.Items {
		_ = builder.AddPod(&pods.Items[i])
	}
	return nil
}

func (c *KubernetesCollector) collectNetworkPolicies(ctx context.Context, builder *graph.Builder, namespace string) error {
	nps, err := c.client.NetworkingV1().NetworkPolicies(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range nps.Items {
		_ = builder.AddNetworkPolicy(&nps.Items[i])
	}
	return nil
}

func (c *KubernetesCollector) collectServices(ctx context.Context, builder *graph.Builder, namespace string) error {
	svcs, err := c.client.CoreV1().Services(namespace).List(ctx, metav1.ListOptions{})
	if err != nil {
		return err
	}

	for i := range svcs.Items {
		_ = builder.AddService(&svcs.Items[i])
	}
	return nil
}

func (c *KubernetesCollector) buildCloudRoleEdges(builder *graph.Builder) {
	sas := builder.Build().GetNodesByType(graph.NodeServiceAccount)

	for _, sa := range sas {
		if sa.Metadata.CloudRoleARN != "" {
			_ = builder.AddCloudRoleEdge(sa.Namespace, sa.Name, "aws", sa.Metadata.CloudRoleARN)
		}
		if sa.Metadata.GCPServiceAccount != "" {
			_ = builder.AddCloudRoleEdge(sa.Namespace, sa.Name, "gcp", sa.Metadata.GCPServiceAccount)
		}
		if sa.Metadata.AzureManagedID != "" {
			_ = builder.AddCloudRoleEdge(sa.Namespace, sa.Name, "azure", sa.Metadata.AzureManagedID)
		}
	}
}

var _ Collector = (*KubernetesCollector)(nil)
