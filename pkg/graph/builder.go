package graph

import (
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
)

type Builder struct {
	graph *Graph
}

func NewBuilder() *Builder {
	return &Builder{
		graph: New(),
	}
}

func (b *Builder) Build() *Graph {
	return b.graph
}

func (b *Builder) AddServiceAccount(sa *corev1.ServiceAccount) error {
	node := NewNode(NodeServiceAccount, sa.Namespace, sa.Name)
	node.Labels = sa.Labels

	if sa.Annotations != nil {
		if arn, ok := sa.Annotations["eks.amazonaws.com/role-arn"]; ok {
			node.Metadata.CloudRoleARN = arn
		}
		if gcpSA, ok := sa.Annotations["iam.gke.io/gcp-service-account"]; ok {
			node.Metadata.GCPServiceAccount = gcpSA
		}
		if azureID, ok := sa.Annotations["azure.workload.identity/client-id"]; ok {
			node.Metadata.AzureManagedID = azureID
		}
	}

	if sa.AutomountServiceAccountToken != nil {
		node.Metadata.AutomountToken = *sa.AutomountServiceAccountToken
	} else {
		node.Metadata.AutomountToken = true
	}

	return b.graph.AddNode(node)
}

func (b *Builder) AddRole(role *rbacv1.Role) error {
	node := NewNode(NodeRole, role.Namespace, role.Name)
	node.Labels = role.Labels
	node.Metadata.IsClusterRole = false
	node.Metadata.Rules = convertRules(role.Rules)

	return b.graph.AddNode(node)
}

func (b *Builder) AddClusterRole(cr *rbacv1.ClusterRole) error {
	node := NewNode(NodeRole, "", cr.Name)
	node.Labels = cr.Labels
	node.Metadata.IsClusterRole = true
	node.Metadata.Rules = convertRules(cr.Rules)

	return b.graph.AddNode(node)
}

func (b *Builder) AddRoleBinding(rb *rbacv1.RoleBinding) error {
	var roleNamespace string
	if rb.RoleRef.Kind == "ClusterRole" {
		roleNamespace = ""
	} else {
		roleNamespace = rb.Namespace
	}
	roleNodeID := GenerateNodeID(NodeRole, roleNamespace, rb.RoleRef.Name)

	for _, subject := range rb.Subjects {
		if subject.Kind != "ServiceAccount" {
			continue
		}

		saNamespace := subject.Namespace
		if saNamespace == "" {
			saNamespace = rb.Namespace
		}

		saNodeID := GenerateNodeID(NodeServiceAccount, saNamespace, subject.Name)

		edge := NewEdge(EdgeBinds, saNodeID, roleNodeID)
		edge.Metadata.BindingName = rb.Name
		edge.Metadata.BindingNamespace = rb.Namespace
		edge.Metadata.IsClusterBinding = false

		_ = b.graph.AddEdge(edge)
	}

	return nil
}

func (b *Builder) AddClusterRoleBinding(crb *rbacv1.ClusterRoleBinding) error {
	roleNodeID := GenerateNodeID(NodeRole, "", crb.RoleRef.Name)

	for _, subject := range crb.Subjects {
		if subject.Kind != "ServiceAccount" {
			continue
		}

		saNodeID := GenerateNodeID(NodeServiceAccount, subject.Namespace, subject.Name)

		edge := NewEdge(EdgeBinds, saNodeID, roleNodeID)
		edge.Metadata.BindingName = crb.Name
		edge.Metadata.IsClusterBinding = true

		_ = b.graph.AddEdge(edge)
	}

	return nil
}

func (b *Builder) AddDeployment(dep *appsv1.Deployment) error {
	node := NewNode(NodeWorkload, dep.Namespace, dep.Name)
	node.Labels = dep.Labels
	node.Metadata.WorkloadKind = "Deployment"
	if dep.Spec.Replicas != nil {
		node.Metadata.Replicas = int(*dep.Spec.Replicas)
	}

	if err := b.graph.AddNode(node); err != nil {
		return err
	}

	saName := dep.Spec.Template.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	saNodeID := GenerateNodeID(NodeServiceAccount, dep.Namespace, saName)
	edge := NewEdge(EdgeUses, node.ID, saNodeID)

	return b.graph.AddEdge(edge)
}

func (b *Builder) AddStatefulSet(sts *appsv1.StatefulSet) error {
	node := NewNode(NodeWorkload, sts.Namespace, sts.Name)
	node.Labels = sts.Labels
	node.Metadata.WorkloadKind = "StatefulSet"
	if sts.Spec.Replicas != nil {
		node.Metadata.Replicas = int(*sts.Spec.Replicas)
	}

	if err := b.graph.AddNode(node); err != nil {
		return err
	}

	saName := sts.Spec.Template.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	saNodeID := GenerateNodeID(NodeServiceAccount, sts.Namespace, saName)
	edge := NewEdge(EdgeUses, node.ID, saNodeID)

	return b.graph.AddEdge(edge)
}

func (b *Builder) AddDaemonSet(ds *appsv1.DaemonSet) error {
	node := NewNode(NodeWorkload, ds.Namespace, ds.Name)
	node.Labels = ds.Labels
	node.Metadata.WorkloadKind = "DaemonSet"

	if err := b.graph.AddNode(node); err != nil {
		return err
	}

	saName := ds.Spec.Template.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	saNodeID := GenerateNodeID(NodeServiceAccount, ds.Namespace, saName)
	edge := NewEdge(EdgeUses, node.ID, saNodeID)

	return b.graph.AddEdge(edge)
}

func (b *Builder) AddJob(job *batchv1.Job) error {
	node := NewNode(NodeWorkload, job.Namespace, job.Name)
	node.Labels = job.Labels
	node.Metadata.WorkloadKind = "Job"

	if err := b.graph.AddNode(node); err != nil {
		return err
	}

	saName := job.Spec.Template.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	saNodeID := GenerateNodeID(NodeServiceAccount, job.Namespace, saName)
	edge := NewEdge(EdgeUses, node.ID, saNodeID)

	return b.graph.AddEdge(edge)
}

func (b *Builder) AddCronJob(cj *batchv1.CronJob) error {
	node := NewNode(NodeWorkload, cj.Namespace, cj.Name)
	node.Labels = cj.Labels
	node.Metadata.WorkloadKind = "CronJob"

	if err := b.graph.AddNode(node); err != nil {
		return err
	}

	saName := cj.Spec.JobTemplate.Spec.Template.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	saNodeID := GenerateNodeID(NodeServiceAccount, cj.Namespace, saName)
	edge := NewEdge(EdgeUses, node.ID, saNodeID)

	return b.graph.AddEdge(edge)
}

func (b *Builder) AddPod(pod *corev1.Pod) error {
	if len(pod.OwnerReferences) > 0 {
		return nil
	}

	node := NewNode(NodeWorkload, pod.Namespace, pod.Name)
	node.Labels = pod.Labels
	node.Metadata.WorkloadKind = "Pod"
	node.Metadata.Replicas = 1

	if err := b.graph.AddNode(node); err != nil {
		return err
	}

	saName := pod.Spec.ServiceAccountName
	if saName == "" {
		saName = "default"
	}
	saNodeID := GenerateNodeID(NodeServiceAccount, pod.Namespace, saName)
	edge := NewEdge(EdgeUses, node.ID, saNodeID)

	return b.graph.AddEdge(edge)
}

func (b *Builder) BuildResourceEdges() {
	roles := b.graph.GetNodesByType(NodeRole)

	for _, role := range roles {
		for _, rule := range role.Metadata.Rules {
			for _, resource := range rule.Resources {
				resourceNode := b.getOrCreateResourceNode(role.Namespace, resource, rule.APIGroups)

				edge := NewEdge(EdgeGrants, role.ID, resourceNode.ID)
				edge.Metadata.Verbs = rule.Verbs
				edge.Metadata.ResourceNames = rule.ResourceNames

				_ = b.graph.AddEdge(edge)
			}
		}
	}
}

func (b *Builder) getOrCreateResourceNode(namespace, resource string, apiGroups []string) *Node {
	resourceID := GenerateNodeID(NodeK8sResource, namespace, resource)

	if existing := b.graph.GetNode(resourceID); existing != nil {
		return existing
	}

	node := NewNode(NodeK8sResource, namespace, resource)
	node.Metadata.ResourceKind = resource

	if len(apiGroups) > 0 && apiGroups[0] != "" {
		node.Labels = map[string]string{"apiGroup": apiGroups[0]}
	}

	_ = b.graph.AddNode(node)
	return node
}

func (b *Builder) AddCloudRoleEdge(saNamespace, saName, cloudProvider, roleIdentifier string) error {
	saNodeID := GenerateNodeID(NodeServiceAccount, saNamespace, saName)
	cloudRoleID := GenerateNodeID(NodeCloudRole, "", roleIdentifier)

	if b.graph.GetNode(cloudRoleID) == nil {
		cloudRoleNode := NewNode(NodeCloudRole, "", roleIdentifier)
		cloudRoleNode.Metadata.CloudProvider = cloudProvider
		_ = b.graph.AddNode(cloudRoleNode)
	}

	edge := NewEdge(EdgeAssumes, saNodeID, cloudRoleID)
	edge.Metadata.CloudProvider = cloudProvider
	edge.Metadata.RoleARN = roleIdentifier

	return b.graph.AddEdge(edge)
}

func (b *Builder) AddCloudRole(id, name, arn, provider string) error {
	node := NewNode(NodeCloudRole, "", name)
	node.ID = id
	node.Metadata.CloudRoleARN = arn
	node.Metadata.CloudProvider = provider

	return b.graph.AddNode(node)
}

func (b *Builder) AddCloudRoleWithPolicies(id, name, arn, provider string, policies []CloudPolicy) error {
	node := NewNode(NodeCloudRole, "", name)
	node.ID = id
	node.Metadata.CloudRoleARN = arn
	node.Metadata.CloudProvider = provider
	node.Metadata.CloudPolicies = policies

	for _, p := range policies {
		if p.ARN != "" {
			node.Metadata.PolicyARNs = append(node.Metadata.PolicyARNs, p.ARN)
		} else {
			node.Metadata.PolicyARNs = append(node.Metadata.PolicyARNs, p.Name)
		}
	}

	return b.graph.AddNode(node)
}

func (b *Builder) AddCloudResource(id, resourceType, arn, provider string) error {
	node := NewNode(NodeCloudResource, "", resourceType)
	node.ID = id
	node.Metadata.CloudRoleARN = arn
	node.Metadata.CloudProvider = provider
	node.Metadata.ResourceKind = resourceType

	return b.graph.AddNode(node)
}

func (b *Builder) AddCloudAssumeEdge(saNodeID, cloudRoleID string) error {
	edge := NewEdge(EdgeAssumes, saNodeID, cloudRoleID)
	return b.graph.AddEdge(edge)
}

func (b *Builder) AddCloudAllowEdge(cloudRoleID, resourceID string, actions []string, severity Severity) error {
	edge := NewEdge(EdgeAllows, cloudRoleID, resourceID)
	edge.Metadata.Verbs = actions
	edge.Metadata.Severity = severity
	return b.graph.AddEdge(edge)
}

func (b *Builder) Graph() *Graph {
	return b.graph
}

func (b *Builder) GetServiceAccountsWithCloudIdentity() []*Node {
	var result []*Node
	for _, node := range b.graph.GetNodesByType(NodeServiceAccount) {
		if node.HasCloudIdentity() {
			result = append(result, node)
		}
	}
	return result
}

func convertRules(policyRules []rbacv1.PolicyRule) []Rule {
	rules := make([]Rule, 0, len(policyRules))
	for _, pr := range policyRules {
		rules = append(rules, Rule{
			APIGroups:     pr.APIGroups,
			Resources:     pr.Resources,
			ResourceNames: pr.ResourceNames,
			Verbs:         pr.Verbs,
		})
	}
	return rules
}

func ParseWorkloadRef(ref, defaultNamespace string) (kind, namespace, name string) {
	parts := strings.Split(ref, "/")

	if len(parts) == 1 {
		return "Deployment", defaultNamespace, parts[0]
	}

	if len(parts) == 2 {
		kindOrNS := strings.ToLower(parts[0])
		switch kindOrNS {
		case "deployment", "deploy", "deployments":
			return "Deployment", defaultNamespace, parts[1]
		case "statefulset", "sts", "statefulsets":
			return "StatefulSet", defaultNamespace, parts[1]
		case "daemonset", "ds", "daemonsets":
			return "DaemonSet", defaultNamespace, parts[1]
		case "job", "jobs":
			return "Job", defaultNamespace, parts[1]
		case "cronjob", "cj", "cronjobs":
			return "CronJob", defaultNamespace, parts[1]
		case "pod", "pods":
			return "Pod", defaultNamespace, parts[1]
		default:
			return "Deployment", parts[0], parts[1]
		}
	}

	if len(parts) == 3 {
		return parts[0], parts[1], parts[2]
	}

	return "Deployment", defaultNamespace, ref
}
