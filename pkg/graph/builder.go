package graph

import (
	"fmt"
	"strings"

	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	networkingv1 "k8s.io/api/networking/v1"
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
	node.Metadata.PodSecurityContext = extractPodSecurityContext(&dep.Spec.Template.Spec)

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
	node.Metadata.PodSecurityContext = extractPodSecurityContext(&sts.Spec.Template.Spec)

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
	node.Metadata.PodSecurityContext = extractPodSecurityContext(&ds.Spec.Template.Spec)

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
	node.Metadata.PodSecurityContext = extractPodSecurityContext(&job.Spec.Template.Spec)

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
	node.Metadata.PodSecurityContext = extractPodSecurityContext(&cj.Spec.JobTemplate.Spec.Template.Spec)

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
	node.Metadata.PodSecurityContext = extractPodSecurityContext(&pod.Spec)

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

func extractPodSecurityContext(podSpec *corev1.PodSpec) *PodSecurityContext {
	psc := &PodSecurityContext{
		HostNetwork: podSpec.HostNetwork,
		HostPID:     podSpec.HostPID,
		HostIPC:     podSpec.HostIPC,
	}

	for _, vol := range podSpec.Volumes {
		if vol.HostPath != nil {
			psc.HostPaths = append(psc.HostPaths, vol.HostPath.Path)
		}
	}

	allContainers := append(podSpec.Containers, podSpec.InitContainers...)
	for _, c := range allContainers {
		csi := ContainerSecurityInfo{
			Name: c.Name,
		}

		if c.SecurityContext != nil {
			csi.HasSecurityContext = true

			if c.SecurityContext.Privileged != nil && *c.SecurityContext.Privileged {
				csi.Privileged = true
			}

			if c.SecurityContext.RunAsUser != nil && *c.SecurityContext.RunAsUser == 0 {
				csi.RunAsRoot = true
			}

			if c.SecurityContext.RunAsNonRoot == nil || !*c.SecurityContext.RunAsNonRoot {
				if c.SecurityContext.RunAsUser == nil {
					csi.RunAsRoot = true
				}
			}

			if c.SecurityContext.AllowPrivilegeEscalation == nil || *c.SecurityContext.AllowPrivilegeEscalation {
				csi.AllowPrivilegeEscalation = true
			}

			if c.SecurityContext.ReadOnlyRootFilesystem != nil && *c.SecurityContext.ReadOnlyRootFilesystem {
				csi.ReadOnlyRootFilesystem = true
			}

			if c.SecurityContext.Capabilities != nil {
				for _, cap := range c.SecurityContext.Capabilities.Add {
					csi.Capabilities = append(csi.Capabilities, string(cap))
				}
			}
		}

		for _, port := range c.Ports {
			if port.HostPort > 0 {
				csi.HostPorts = append(csi.HostPorts, port.HostPort)
			}
		}

		for _, env := range c.Env {
			if env.ValueFrom != nil && env.ValueFrom.SecretKeyRef != nil {
				csi.SecretsInEnv++
			}
		}

		for _, envFrom := range c.EnvFrom {
			if envFrom.SecretRef != nil {
				csi.SecretsInEnv++
			}
		}

		psc.Containers = append(psc.Containers, csi)
	}

	return psc
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

func (b *Builder) AddNetworkPolicy(np *networkingv1.NetworkPolicy) error {
	node := NewNode(NodeNetworkPolicy, np.Namespace, np.Name)
	node.Labels = np.Labels

	npInfo := &NetworkPolicyInfo{
		PodSelector: np.Spec.PodSelector.MatchLabels,
	}

	for _, pt := range np.Spec.PolicyTypes {
		npInfo.PolicyTypes = append(npInfo.PolicyTypes, string(pt))
	}

	// Check for deny-all or allow-all ingress
	hasIngress := false
	for _, pt := range np.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeIngress {
			hasIngress = true
			break
		}
	}
	if hasIngress && len(np.Spec.Ingress) == 0 {
		npInfo.DenyAllIngress = true
	}

	// Check for deny-all or allow-all egress
	hasEgress := false
	for _, pt := range np.Spec.PolicyTypes {
		if pt == networkingv1.PolicyTypeEgress {
			hasEgress = true
			break
		}
	}
	if hasEgress && len(np.Spec.Egress) == 0 {
		npInfo.DenyAllEgress = true
	}

	// Parse ingress rules
	for _, ingress := range np.Spec.Ingress {
		// Empty From means allow all
		if len(ingress.From) == 0 && len(ingress.Ports) == 0 {
			npInfo.AllowAllIngress = true
		}

		for _, from := range ingress.From {
			rule := NetworkPolicyRule{}
			if from.PodSelector != nil {
				rule.FromPodSelector = from.PodSelector.MatchLabels
			}
			if from.NamespaceSelector != nil {
				rule.FromNamespaceSelector = from.NamespaceSelector.MatchLabels
			}
			if from.IPBlock != nil {
				rule.FromIPBlock = from.IPBlock.CIDR
			}
			for _, port := range ingress.Ports {
				pp := PolicyPort{Protocol: string(*port.Protocol)}
				if port.Port != nil {
					pp.Port = port.Port.String()
				}
				rule.Ports = append(rule.Ports, pp)
			}
			npInfo.IngressRules = append(npInfo.IngressRules, rule)
		}
	}

	// Parse egress rules
	for _, egress := range np.Spec.Egress {
		// Empty To means allow all
		if len(egress.To) == 0 && len(egress.Ports) == 0 {
			npInfo.AllowAllEgress = true
		}

		for _, to := range egress.To {
			rule := NetworkPolicyRule{}
			if to.PodSelector != nil {
				rule.ToPodSelector = to.PodSelector.MatchLabels
			}
			if to.NamespaceSelector != nil {
				rule.ToNamespaceSelector = to.NamespaceSelector.MatchLabels
			}
			if to.IPBlock != nil {
				rule.ToIPBlock = to.IPBlock.CIDR
			}
			for _, port := range egress.Ports {
				pp := PolicyPort{Protocol: string(*port.Protocol)}
				if port.Port != nil {
					pp.Port = port.Port.String()
				}
				rule.Ports = append(rule.Ports, pp)
			}
			npInfo.EgressRules = append(npInfo.EgressRules, rule)
		}
	}

	node.Metadata.NetworkPolicy = npInfo
	return b.graph.AddNode(node)
}

func (b *Builder) AddService(svc *corev1.Service) error {
	node := NewNode(NodeService, svc.Namespace, svc.Name)
	node.Labels = svc.Labels

	svcInfo := &ServiceInfo{
		ServiceType:    string(svc.Spec.Type),
		ClusterIP:      svc.Spec.ClusterIP,
		ExternalIPs:    svc.Spec.ExternalIPs,
		LoadBalancerIP: svc.Spec.LoadBalancerIP,
		Selector:       svc.Spec.Selector,
	}

	for _, port := range svc.Spec.Ports {
		sp := ServicePort{
			Name:       port.Name,
			Port:       port.Port,
			TargetPort: port.TargetPort.String(),
			NodePort:   port.NodePort,
			Protocol:   string(port.Protocol),
		}
		svcInfo.Ports = append(svcInfo.Ports, sp)
	}

	node.Metadata.ServiceInfo = svcInfo
	return b.graph.AddNode(node)
}

func (b *Builder) GetWorkloadNetworkExposure(workloadID string) *WorkloadNetworkExposure {
	workload := b.graph.GetNode(workloadID)
	if workload == nil {
		return nil
	}

	exposure := &WorkloadNetworkExposure{
		WorkloadID:        workloadID,
		WorkloadName:      workload.Name,
		WorkloadNamespace: workload.Namespace,
		WorkloadKind:      workload.Metadata.WorkloadKind,
	}

	// Find network policies that select this workload
	for _, np := range b.graph.GetNodesByType(NodeNetworkPolicy) {
		if np.Namespace != workload.Namespace {
			continue
		}
		if matchLabels(workload.Labels, np.Metadata.NetworkPolicy.PodSelector) {
			exposure.NetworkPolicies = append(exposure.NetworkPolicies, np.Name)
			exposure.HasIngressPolicy = exposure.HasIngressPolicy || hasIngressPolicy(np)
			exposure.HasEgressPolicy = exposure.HasEgressPolicy || hasEgressPolicy(np)
		}
	}

	// Find services that select this workload
	for _, svc := range b.graph.GetNodesByType(NodeService) {
		if svc.Namespace != workload.Namespace {
			continue
		}
		if svc.Metadata.ServiceInfo != nil && matchLabels(workload.Labels, svc.Metadata.ServiceInfo.Selector) {
			exposure.Services = append(exposure.Services, ServiceExposure{
				Name:        svc.Name,
				Type:        svc.Metadata.ServiceInfo.ServiceType,
				ExternalIPs: svc.Metadata.ServiceInfo.ExternalIPs,
				Ports:       svc.Metadata.ServiceInfo.Ports,
			})
			if svc.Metadata.ServiceInfo.ServiceType == "LoadBalancer" ||
				svc.Metadata.ServiceInfo.ServiceType == "NodePort" {
				exposure.IsExternallyExposed = true
			}
		}
	}

	return exposure
}

type WorkloadNetworkExposure struct {
	WorkloadID          string
	WorkloadName        string
	WorkloadNamespace   string
	WorkloadKind        string
	NetworkPolicies     []string
	HasIngressPolicy    bool
	HasEgressPolicy     bool
	Services            []ServiceExposure
	IsExternallyExposed bool
}

type ServiceExposure struct {
	Name        string
	Type        string
	ExternalIPs []string
	Ports       []ServicePort
}

func matchLabels(workloadLabels, selector map[string]string) bool {
	if len(selector) == 0 {
		return true // Empty selector matches all
	}
	for k, v := range selector {
		if workloadLabels[k] != v {
			return false
		}
	}
	return true
}

func hasIngressPolicy(np *Node) bool {
	for _, pt := range np.Metadata.NetworkPolicy.PolicyTypes {
		if pt == "Ingress" {
			return true
		}
	}
	return false
}

func hasEgressPolicy(np *Node) bool {
	for _, pt := range np.Metadata.NetworkPolicy.PolicyTypes {
		if pt == "Egress" {
			return true
		}
	}
	return false
}

// Placeholder to use fmt import
var _ = fmt.Sprintf
