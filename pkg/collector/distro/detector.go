// Package distro provides platform/distribution detection for Kubernetes clusters.
// It detects whether the cluster is vanilla kubeadm, EKS, GKE, AKS, OpenShift,
// RKE2, K3s, etc. and exposes a DistroProfile that the rest of the codebase can
// use to adjust security analysis behaviour.
package distro

import (
	"context"
	"strings"

	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/kubernetes"
)

// ---------------------------------------------------------------------------
// DistroProfile
// ---------------------------------------------------------------------------

// DistroProfile carries all the distro-specific metadata discovered at
// detection time. It is designed to be serialisable so that it can be stored
// on the graph and consulted during analysis.
type DistroProfile struct {
	// Platform is a normalised identifier, e.g. "vanilla", "eks", "gke",
	// "aks", "openshift", "rke2", "k3s".
	Platform string `json:"platform"`
	// CloudProvider is the underlying cloud: "aws", "gcp", "azure", or "".
	CloudProvider string `json:"cloud_provider,omitempty"`
	// SystemNamespacePrefixes lists namespace name-prefixes that should be
	// treated as system namespaces for this distro (in addition to the
	// standard kube-system / kube-public / kube-node-lease).
	SystemNamespacePrefixes []string `json:"system_namespace_prefixes,omitempty"`
	// FeatureFlags captures distro-specific boolean capabilities.
	FeatureFlags map[string]bool `json:"feature_flags,omitempty"`
}

// IsSystemNamespace returns true when the given namespace should be treated as
// a system namespace given the detected DistroProfile.
func (p DistroProfile) IsSystemNamespace(ns string) bool {
	// Standard Kubernetes system namespaces.
	switch ns {
	case "kube-system", "kube-public", "kube-node-lease":
		return true
	}
	for _, prefix := range p.SystemNamespacePrefixes {
		if strings.HasPrefix(ns, prefix) {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// Detector interface
// ---------------------------------------------------------------------------

// Detector is implemented by each platform-specific detector.
type Detector interface {
	// Detect probes the cluster and returns a DistroProfile.
	Detect(ctx context.Context, client kubernetes.Interface) (DistroProfile, error)
}

// ---------------------------------------------------------------------------
// GenericDetector – vanilla kubeadm / upstream Kubernetes
// ---------------------------------------------------------------------------

// GenericDetector is the fallback detector for vanilla Kubernetes clusters.
type GenericDetector struct{}

func (d *GenericDetector) Detect(_ context.Context, _ kubernetes.Interface) (DistroProfile, error) {
	return DistroProfile{
		Platform:     "vanilla",
		FeatureFlags: map[string]bool{},
	}, nil
}

// ---------------------------------------------------------------------------
// OpenShiftDetector
// ---------------------------------------------------------------------------

// OpenShiftDetector recognises OpenShift clusters by checking for the
// SecurityContextConstraints CRD (present on all OCP 3.x/4.x clusters).
type OpenShiftDetector struct {
	DynamicClient dynamic.Interface
}

func (d *OpenShiftDetector) Detect(ctx context.Context, client kubernetes.Interface) (DistroProfile, error) {
	profile := DistroProfile{
		Platform:     "vanilla",
		FeatureFlags: map[string]bool{},
	}

	// Check for the SecurityContextConstraints CRD via dynamic client.
	if d.DynamicClient != nil {
		sccGVR := schema.GroupVersionResource{
			Group:    "security.openshift.io",
			Version:  "v1",
			Resource: "securitycontextconstraints",
		}
		_, err := d.DynamicClient.Resource(sccGVR).List(ctx, metav1.ListOptions{Limit: 1})
		if err == nil {
			profile.Platform = "openshift"
			profile.FeatureFlags["scc"] = true
			profile.SystemNamespacePrefixes = []string{"openshift-"}
			return profile, nil
		}
	}

	// Fallback: check for OpenShift-specific namespaces.
	nsList, err := client.CoreV1().Namespaces().List(ctx, metav1.ListOptions{})
	if err != nil {
		return profile, nil //nolint:nilerr // non-fatal; fall through to generic
	}
	for _, ns := range nsList.Items {
		if strings.HasPrefix(ns.Name, "openshift-") {
			profile.Platform = "openshift"
			profile.FeatureFlags["scc"] = true
			profile.SystemNamespacePrefixes = []string{"openshift-"}
			return profile, nil
		}
	}

	return profile, nil
}

// ---------------------------------------------------------------------------
// EKSDetector
// ---------------------------------------------------------------------------

// EKSDetector recognises Amazon EKS by checking node labels.
type EKSDetector struct{}

func (d *EKSDetector) Detect(ctx context.Context, client kubernetes.Interface) (DistroProfile, error) {
	profile := DistroProfile{
		Platform:     "vanilla",
		CloudProvider: "aws",
		FeatureFlags: map[string]bool{},
	}

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return profile, nil //nolint:nilerr
	}

	for _, node := range nodes.Items {
		for k := range node.Labels {
			if strings.HasPrefix(k, "eks.amazonaws.com/") ||
				strings.HasPrefix(k, "alpha.eksctl.io/") ||
				strings.HasPrefix(k, "beta.kubernetes.io/") && node.Labels["beta.kubernetes.io/os"] == "linux" {
				profile.Platform = "eks"
				profile.FeatureFlags["irsa"] = true
				return profile, nil
			}
		}
		// Check for aws-node daemonset as secondary signal.
		_, ok := node.Labels["kubernetes.io/arch"]
		if ok {
			// Probe for aws-node daemonset
			_, dsErr := client.AppsV1().DaemonSets("kube-system").Get(ctx, "aws-node", metav1.GetOptions{})
			if dsErr == nil {
				profile.Platform = "eks"
				profile.FeatureFlags["irsa"] = true
				return profile, nil
			}
		}
	}

	return profile, nil
}

// ---------------------------------------------------------------------------
// GKEDetector
// ---------------------------------------------------------------------------

// GKEDetector recognises Google Kubernetes Engine by node labels.
type GKEDetector struct{}

func (d *GKEDetector) Detect(ctx context.Context, client kubernetes.Interface) (DistroProfile, error) {
	profile := DistroProfile{
		Platform:     "vanilla",
		CloudProvider: "gcp",
		FeatureFlags: map[string]bool{},
	}

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return profile, nil //nolint:nilerr
	}

	for _, node := range nodes.Items {
		for k := range node.Labels {
			if strings.HasPrefix(k, "cloud.google.com/gke-") ||
				strings.HasPrefix(k, "beta.kubernetes.io/fluentd-ds-ready") {
				profile.Platform = "gke"
				profile.FeatureFlags["workload_identity"] = true
				return profile, nil
			}
		}
	}

	return profile, nil
}

// ---------------------------------------------------------------------------
// AKSDetector
// ---------------------------------------------------------------------------

// AKSDetector recognises Azure Kubernetes Service by node labels.
type AKSDetector struct{}

func (d *AKSDetector) Detect(ctx context.Context, client kubernetes.Interface) (DistroProfile, error) {
	profile := DistroProfile{
		Platform:     "vanilla",
		CloudProvider: "azure",
		FeatureFlags: map[string]bool{},
	}

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return profile, nil //nolint:nilerr
	}

	for _, node := range nodes.Items {
		for k := range node.Labels {
			if strings.HasPrefix(k, "kubernetes.azure.com/") ||
				strings.HasPrefix(k, "agentpool") {
				profile.Platform = "aks"
				profile.FeatureFlags["managed_identity"] = true
				return profile, nil
			}
		}
	}

	return profile, nil
}

// ---------------------------------------------------------------------------
// RKE2Detector
// ---------------------------------------------------------------------------

// RKE2Detector recognises Rancher Kubernetes Engine 2 (RKE2) by node annotations.
type RKE2Detector struct{}

func (d *RKE2Detector) Detect(ctx context.Context, client kubernetes.Interface) (DistroProfile, error) {
	profile := DistroProfile{
		Platform:     "vanilla",
		FeatureFlags: map[string]bool{},
		SystemNamespacePrefixes: []string{"cattle-", "fleet-", "rancher-"},
	}

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return profile, nil //nolint:nilerr
	}

	for _, node := range nodes.Items {
		for k := range node.Annotations {
			if strings.HasPrefix(k, "rke2.io/") {
				profile.Platform = "rke2"
				return profile, nil
			}
		}
		for k := range node.Labels {
			if strings.HasPrefix(k, "rke.cattle.io/") {
				profile.Platform = "rke2"
				return profile, nil
			}
		}
	}

	return profile, nil
}

// ---------------------------------------------------------------------------
// K3sDetector
// ---------------------------------------------------------------------------

// K3sDetector recognises K3s by node annotations and labels.
type K3sDetector struct{}

func (d *K3sDetector) Detect(ctx context.Context, client kubernetes.Interface) (DistroProfile, error) {
	profile := DistroProfile{
		Platform:     "vanilla",
		FeatureFlags: map[string]bool{},
	}

	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return profile, nil //nolint:nilerr
	}

	for _, node := range nodes.Items {
		for k := range node.Annotations {
			if strings.HasPrefix(k, "k3s.io/") {
				profile.Platform = "k3s"
				return profile, nil
			}
		}
		for k := range node.Labels {
			if strings.HasPrefix(k, "k3s.io/") || k == "node.k3s.io/type" {
				profile.Platform = "k3s"
				return profile, nil
			}
		}
	}

	return profile, nil
}

// ---------------------------------------------------------------------------
// AutoDetect – runs all detectors in priority order
// ---------------------------------------------------------------------------

// AutoDetect runs all built-in detectors in priority order and returns the
// first non-generic match. If none match, it returns a vanilla profile.
func AutoDetect(ctx context.Context, client kubernetes.Interface, dynClient dynamic.Interface) DistroProfile {
	detectors := []Detector{
		&OpenShiftDetector{DynamicClient: dynClient},
		&EKSDetector{},
		&GKEDetector{},
		&AKSDetector{},
		&RKE2Detector{},
		&K3sDetector{},
		&GenericDetector{},
	}

	for _, d := range detectors {
		profile, err := d.Detect(ctx, client)
		if err != nil {
			continue
		}
		if profile.Platform != "vanilla" {
			return profile
		}
	}

	return DistroProfile{
		Platform:     "vanilla",
		FeatureFlags: map[string]bool{},
	}
}
