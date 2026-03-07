package distro

import (
	"context"
	"strings"

	"github.com/nelssec/identity-chain/pkg/analysis"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/client-go/kubernetes"
)

// Detector detects the Kubernetes distribution and cloud provider.
type Detector interface {
	Detect(ctx context.Context, client kubernetes.Interface) (analysis.DistroProfile, error)
}

// AutoDetect runs all known detectors and returns the first match.
func AutoDetect(ctx context.Context, client kubernetes.Interface) (analysis.DistroProfile, error) {
	detectors := []Detector{
		&OpenShiftDetector{},
		&EKSDetector{},
		&GKEDetector{},
		&AKSDetector{},
		&RKE2Detector{},
		&K3sDetector{},
	}
	for _, d := range detectors {
		profile, err := d.Detect(ctx, client)
		if err != nil {
			continue
		}
		if profile.Platform != "kubernetes" {
			return profile, nil
		}
	}
	return (&GenericDetector{}).Detect(ctx, client)
}

// GenericDetector detects vanilla Kubernetes.
type GenericDetector struct{}

func (d *GenericDetector) Detect(_ context.Context, _ kubernetes.Interface) (analysis.DistroProfile, error) {
	return analysis.DistroProfile{
		Platform:                "kubernetes",
		CloudProvider:           "unknown",
		SystemNamespacePrefixes: analysis.DefaultSystemNamespacePrefixes(),
		FeatureFlags:            map[string]bool{},
	}, nil
}

// OpenShiftDetector checks for OpenShift by looking for SCC CRDs.
type OpenShiftDetector struct{}

func (d *OpenShiftDetector) Detect(ctx context.Context, client kubernetes.Interface) (analysis.DistroProfile, error) {
	_, resources, err := client.Discovery().ServerGroupsAndResources()
	if err != nil {
		return analysis.DistroProfile{Platform: "kubernetes"}, err
	}
	for _, list := range resources {
		for _, r := range list.APIResources {
			if r.Kind == "SecurityContextConstraints" {
				return analysis.DistroProfile{
					Platform:                "openshift",
					CloudProvider:           "unknown",
					SystemNamespacePrefixes: append(analysis.DefaultSystemNamespacePrefixes(), "openshift-"),
					FeatureFlags:            map[string]bool{"scc": true},
				}, nil
			}
		}
	}
	return analysis.DistroProfile{Platform: "kubernetes"}, nil
}

// EKSDetector checks for EKS by looking for eks.amazonaws.com/ node labels or aws-node daemonset.
type EKSDetector struct{}

func (d *EKSDetector) Detect(ctx context.Context, client kubernetes.Interface) (analysis.DistroProfile, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return analysis.DistroProfile{Platform: "kubernetes"}, err
	}
	for _, node := range nodes.Items {
		for k := range node.Labels {
			if strings.HasPrefix(k, "eks.amazonaws.com/") {
				return eksProfile(), nil
			}
		}
	}
	_, err = client.AppsV1().DaemonSets("kube-system").Get(ctx, "aws-node", metav1.GetOptions{})
	if err == nil {
		return eksProfile(), nil
	}
	return analysis.DistroProfile{Platform: "kubernetes"}, nil
}

func eksProfile() analysis.DistroProfile {
	return analysis.DistroProfile{
		Platform:                "eks",
		CloudProvider:           "aws",
		SystemNamespacePrefixes: append(analysis.DefaultSystemNamespacePrefixes(), "amazon-", "aws-"),
		FeatureFlags:            map[string]bool{"irsa": true},
	}
}

// GKEDetector checks for GKE by looking for cloud.google.com/gke-nodepool node labels.
type GKEDetector struct{}

func (d *GKEDetector) Detect(ctx context.Context, client kubernetes.Interface) (analysis.DistroProfile, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return analysis.DistroProfile{Platform: "kubernetes"}, err
	}
	for _, node := range nodes.Items {
		if _, ok := node.Labels["cloud.google.com/gke-nodepool"]; ok {
			return analysis.DistroProfile{
				Platform:                "gke",
				CloudProvider:           "gcp",
				SystemNamespacePrefixes: append(analysis.DefaultSystemNamespacePrefixes(), "gke-"),
				FeatureFlags:            map[string]bool{"workload_identity": true},
			}, nil
		}
	}
	return analysis.DistroProfile{Platform: "kubernetes"}, nil
}

// AKSDetector checks for AKS by looking for kubernetes.azure.com/ node labels.
type AKSDetector struct{}

func (d *AKSDetector) Detect(ctx context.Context, client kubernetes.Interface) (analysis.DistroProfile, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return analysis.DistroProfile{Platform: "kubernetes"}, err
	}
	for _, node := range nodes.Items {
		for k := range node.Labels {
			if strings.HasPrefix(k, "kubernetes.azure.com/") {
				return analysis.DistroProfile{
					Platform:                "aks",
					CloudProvider:           "azure",
					SystemNamespacePrefixes: append(analysis.DefaultSystemNamespacePrefixes(), "azure-"),
					FeatureFlags:            map[string]bool{"workload_identity": true},
				}, nil
			}
		}
	}
	return analysis.DistroProfile{Platform: "kubernetes"}, nil
}

// RKE2Detector checks for RKE2 by looking for rke2 annotations on nodes.
type RKE2Detector struct{}

func (d *RKE2Detector) Detect(ctx context.Context, client kubernetes.Interface) (analysis.DistroProfile, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return analysis.DistroProfile{Platform: "kubernetes"}, err
	}
	for _, node := range nodes.Items {
		for k := range node.Annotations {
			if strings.Contains(k, "rke2") {
				return analysis.DistroProfile{
					Platform:                "rke2",
					CloudProvider:           "unknown",
					SystemNamespacePrefixes: append(analysis.DefaultSystemNamespacePrefixes(), "cattle-"),
					FeatureFlags:            map[string]bool{},
				}, nil
			}
		}
		for k := range node.Labels {
			if strings.Contains(k, "rke2") {
				return analysis.DistroProfile{
					Platform:                "rke2",
					CloudProvider:           "unknown",
					SystemNamespacePrefixes: append(analysis.DefaultSystemNamespacePrefixes(), "cattle-"),
					FeatureFlags:            map[string]bool{},
				}, nil
			}
		}
	}
	return analysis.DistroProfile{Platform: "kubernetes"}, nil
}

// K3sDetector checks for k3s by looking for k3s annotations on nodes.
type K3sDetector struct{}

func (d *K3sDetector) Detect(ctx context.Context, client kubernetes.Interface) (analysis.DistroProfile, error) {
	nodes, err := client.CoreV1().Nodes().List(ctx, metav1.ListOptions{Limit: 5})
	if err != nil {
		return analysis.DistroProfile{Platform: "kubernetes"}, err
	}
	for _, node := range nodes.Items {
		for k := range node.Annotations {
			if strings.Contains(k, "k3s") {
				return analysis.DistroProfile{
					Platform:                "k3s",
					CloudProvider:           "unknown",
					SystemNamespacePrefixes: analysis.DefaultSystemNamespacePrefixes(),
					FeatureFlags:            map[string]bool{},
				}, nil
			}
		}
		for k := range node.Labels {
			if strings.Contains(k, "k3s") {
				return analysis.DistroProfile{
					Platform:                "k3s",
					CloudProvider:           "unknown",
					SystemNamespacePrefixes: analysis.DefaultSystemNamespacePrefixes(),
					FeatureFlags:            map[string]bool{},
				}, nil
			}
		}
	}
	return analysis.DistroProfile{Platform: "kubernetes"}, nil
}
