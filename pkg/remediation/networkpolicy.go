package remediation

import (
	"fmt"

	"github.com/nelssec/identity-chain/pkg/analysis"
)

func GenerateNetworkPolicyRemediations(findings []analysis.NetworkPolicyFinding) []Remediation {
	var remediations []Remediation
	nsProcessed := make(map[string]bool)

	for _, f := range findings {
		rems := generateNetworkPolicyRemediation(f, nsProcessed)
		remediations = append(remediations, rems...)
	}

	return remediations
}

func generateNetworkPolicyRemediation(f analysis.NetworkPolicyFinding, nsProcessed map[string]bool) []Remediation {
	var remediations []Remediation

	for _, affected := range f.Affected {
		r := generateNetworkPolicyRemediationForAffected(f, affected, nsProcessed)
		if r != nil {
			remediations = append(remediations, *r)
		}
	}

	return remediations
}

func generateNetworkPolicyRemediationForAffected(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource, nsProcessed map[string]bool) *Remediation {
	switch f.CheckID {
	case "NET001":
		return remediateNoNetworkPolicy(f, affected, nsProcessed)
	case "NET002":
		return remediateNoDefaultDeny(f, affected, nsProcessed)
	case "NET003":
		return remediateNoIngressPolicy(f, affected, nsProcessed)
	case "NET004":
		return remediateNoEgressPolicy(f, affected, nsProcessed)
	case "NET005":
		return remediateAllowAllIngress(f, affected)
	case "NET006":
		return remediateAllowAllEgress(f, affected)
	case "NET007":
		return remediateWideCIDR(f, affected)
	case "NET008":
		return remediateAllNamespaces(f, affected)
	default:
		return nil
	}
}

func remediateNoNetworkPolicy(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource, nsProcessed map[string]bool) *Remediation {
	ns := affected.Namespace
	if nsProcessed[ns+"-default-deny"] {
		return nil
	}
	nsProcessed[ns+"-default-deny"] = true

	r := &Remediation{
		Type:        RemediationNetworkPolicy,
		FindingID:   fmt.Sprintf("%s-%s", f.CheckID, ns),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "Namespace",
			Name:      ns,
			Namespace: ns,
		},
		Action: "Create default-deny network policy",
	}

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: fmt.Sprintf("Create default-deny-all policy for namespace %s", ns),
			YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`, ns),
		},
		{
			Action:      "create",
			Description: "Allow DNS egress (required for most workloads)",
			YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53`, ns),
		},
	}

	return r
}

func remediateNoDefaultDeny(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource, nsProcessed map[string]bool) *Remediation {
	ns := affected.Namespace
	if nsProcessed[ns+"-default-deny"] {
		return nil
	}
	nsProcessed[ns+"-default-deny"] = true

	r := &Remediation{
		Type:        RemediationNetworkPolicy,
		FindingID:   fmt.Sprintf("%s-%s", f.CheckID, ns),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "Namespace",
			Name:      ns,
			Namespace: ns,
		},
		Action: "Add default-deny network policy",
	}

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: fmt.Sprintf("Create default-deny-all policy for namespace %s", ns),
			YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-all
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress
  - Egress`, ns),
		},
	}

	return r
}

func remediateNoIngressPolicy(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource, nsProcessed map[string]bool) *Remediation {
	ns := affected.Namespace
	if nsProcessed[ns+"-ingress"] {
		return nil
	}
	nsProcessed[ns+"-ingress"] = true

	r := &Remediation{
		Type:        RemediationNetworkPolicy,
		FindingID:   fmt.Sprintf("%s-%s", f.CheckID, ns),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "Namespace",
			Name:      ns,
			Namespace: ns,
		},
		Action: "Add default-deny ingress policy",
	}

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: fmt.Sprintf("Create default-deny-ingress policy for namespace %s", ns),
			YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-ingress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Ingress`, ns),
		},
	}

	return r
}

func remediateNoEgressPolicy(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource, nsProcessed map[string]bool) *Remediation {
	ns := affected.Namespace
	if nsProcessed[ns+"-egress"] {
		return nil
	}
	nsProcessed[ns+"-egress"] = true

	r := &Remediation{
		Type:        RemediationNetworkPolicy,
		FindingID:   fmt.Sprintf("%s-%s", f.CheckID, ns),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "Namespace",
			Name:      ns,
			Namespace: ns,
		},
		Action: "Add default-deny egress policy",
	}

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: fmt.Sprintf("Create default-deny-egress policy for namespace %s", ns),
			YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: default-deny-egress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Egress`, ns),
		},
		{
			Action:      "create",
			Description: "Allow DNS egress (required for most workloads)",
			YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: allow-dns-egress
  namespace: %s
spec:
  podSelector: {}
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
    - protocol: TCP
      port: 53`, ns),
		},
	}

	return r
}

func remediateAllowAllIngress(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource) *Remediation {
	r := &Remediation{
		Type:        RemediationNetworkPolicy,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "NetworkPolicy",
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Restrict overly permissive ingress rules",
	}

	r.Manifests = []Manifest{
		{
			Action:      "replace",
			Description: fmt.Sprintf("Replace allow-all ingress in policy %s with specific rules", affected.Name),
			YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: %s
spec:
  podSelector:
    matchLabels:
      app: your-app
  policyTypes:
  - Ingress
  ingress:
  - from:
    - podSelector:
        matchLabels:
          app: allowed-client
    ports:
    - protocol: TCP
      port: 8080`, affected.Name, affected.Namespace),
		},
	}

	return r
}

func remediateAllowAllEgress(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource) *Remediation {
	r := &Remediation{
		Type:        RemediationNetworkPolicy,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "NetworkPolicy",
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Restrict overly permissive egress rules",
	}

	r.Manifests = []Manifest{
		{
			Action:      "replace",
			Description: fmt.Sprintf("Replace allow-all egress in policy %s with specific rules", affected.Name),
			YAML: fmt.Sprintf(`apiVersion: networking.k8s.io/v1
kind: NetworkPolicy
metadata:
  name: %s
  namespace: %s
spec:
  podSelector:
    matchLabels:
      app: your-app
  policyTypes:
  - Egress
  egress:
  - to:
    - namespaceSelector:
        matchLabels:
          kubernetes.io/metadata.name: kube-system
    ports:
    - protocol: UDP
      port: 53
  - to:
    - podSelector:
        matchLabels:
          app: database
    ports:
    - protocol: TCP
      port: 5432`, affected.Name, affected.Namespace),
		},
	}

	return r
}

func remediateWideCIDR(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource) *Remediation {
	r := &Remediation{
		Type:        RemediationNetworkPolicy,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "NetworkPolicy",
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Replace wide CIDR with specific ranges",
	}

	r.Manifests = []Manifest{
		{
			Action:      "replace",
			Description: "Replace 0.0.0.0/0 with specific CIDR ranges",
			YAML: fmt.Sprintf(`# Review and update NetworkPolicy %s in namespace %s
# Replace wide CIDR ranges with specific IPs/ranges:
#
# Instead of:
#   - ipBlock:
#       cidr: 0.0.0.0/0
#
# Use specific ranges:
#   - ipBlock:
#       cidr: 10.0.0.0/8
#       except:
#       - 10.0.0.0/24
#   - ipBlock:
#       cidr: 192.168.1.0/24
#
# Or use pod/namespace selectors instead of IP blocks when possible`, affected.Name, affected.Namespace),
		},
	}

	return r
}

func remediateAllNamespaces(f analysis.NetworkPolicyFinding, affected analysis.AffectedNetworkResource) *Remediation {
	r := &Remediation{
		Type:        RemediationNetworkPolicy,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "NetworkPolicy",
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Restrict namespace selector to specific namespaces",
	}

	r.Manifests = []Manifest{
		{
			Action:      "replace",
			Description: "Replace empty namespaceSelector with specific labels",
			YAML: fmt.Sprintf(`# Review and update NetworkPolicy %s in namespace %s
# Replace empty namespaceSelector (allows all namespaces) with specific labels:
#
# Instead of:
#   - namespaceSelector: {}
#
# Use:
#   - namespaceSelector:
#       matchLabels:
#         environment: production
#   - namespaceSelector:
#       matchLabels:
#         kubernetes.io/metadata.name: trusted-namespace`, affected.Name, affected.Namespace),
		},
	}

	return r
}
