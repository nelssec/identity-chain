package remediation

import (
	"fmt"
	"strings"

	"github.com/nelssec/identity-chain/pkg/analysis"
)

func GenerateRBACRemediations(findings []analysis.RBACFinding) []Remediation {
	var remediations []Remediation

	for _, f := range findings {
		rems := generateRBACRemediation(f)
		remediations = append(remediations, rems...)
	}

	return remediations
}

func generateRBACRemediation(f analysis.RBACFinding) []Remediation {
	var remediations []Remediation

	for _, affected := range f.Affected {
		r := generateRBACRemediationForAffected(f, affected)
		if r != nil {
			remediations = append(remediations, *r)
		}
	}

	return remediations
}

func generateRBACRemediationForAffected(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	switch f.CheckID {
	case "RBAC001", "RBAC002":
		return remediateClusterAdmin(f, affected)
	case "RBAC003", "RBAC012":
		return remediateSecretsAccess(f, affected)
	case "RBAC004", "RBAC015":
		return remediateWildcardPermissions(f, affected)
	case "RBAC005":
		return remediateDefaultServiceAccount(f, affected)
	case "RBAC006":
		return remediateAutoMountToken(f, affected)
	case "RBAC007":
		return remediatePodCreateAccess(f, affected)
	case "RBAC008", "RBAC009", "RBAC010", "RBAC013", "RBAC014":
		return remediateEscalationPermissions(f, affected)
	case "RBAC011":
		return remediateNodeAccess(f, affected)
	default:
		return nil
	}
}

func remediateClusterAdmin(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	r := &Remediation{
		Type:        RemediationRBAC,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Replace cluster-admin with least-privilege role",
	}

	subjectName := strings.ReplaceAll(affected.Name, ":", "-")
	subjectName = strings.ReplaceAll(subjectName, "/", "-")
	roleName := fmt.Sprintf("%s-least-priv", subjectName)

	var roleYAML string
	if affected.Namespace != "" && affected.Namespace != "cluster-wide" {
		roleYAML = fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %s
  namespace: %s
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]`, roleName, affected.Namespace)
	} else {
		roleYAML = fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]`, roleName)
	}

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: fmt.Sprintf("Create least-privilege role %s", roleName),
			YAML:        roleYAML,
		},
		{
			Action:      "update",
			Description: fmt.Sprintf("Update binding %s to use new role", affected.Name),
			YAML:        fmt.Sprintf("# Update %s to reference %s instead of cluster-admin", affected.Name, roleName),
		},
	}

	return r
}

func remediateSecretsAccess(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	r := &Remediation{
		Type:        RemediationRBAC,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Remove secrets access from role",
	}

	roleName := affected.Name + "-no-secrets"
	var yaml string

	if affected.Kind == "ClusterRole" || affected.Namespace == "" {
		yaml = fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]`, roleName)
	} else {
		yaml = fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %s
  namespace: %s
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps"]
  verbs: ["get", "list", "watch"]`, roleName, affected.Namespace)
	}

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: "Create role without secrets access",
			YAML:        yaml,
		},
	}

	return r
}

func remediateWildcardPermissions(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	r := &Remediation{
		Type:        RemediationRBAC,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Replace wildcards with explicit permissions",
	}

	roleName := affected.Name + "-explicit"
	var yaml string

	if affected.Kind == "ClusterRole" || affected.Namespace == "" {
		yaml = fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]`, roleName)
	} else {
		yaml = fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %s
  namespace: %s
rules:
- apiGroups: [""]
  resources: ["pods", "services", "configmaps", "endpoints"]
  verbs: ["get", "list", "watch"]
- apiGroups: ["apps"]
  resources: ["deployments", "replicasets"]
  verbs: ["get", "list", "watch"]`, roleName, affected.Namespace)
	}

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: "Create role with explicit permissions (adjust based on actual needs)",
			YAML:        yaml,
		},
	}

	return r
}

func remediateDefaultServiceAccount(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	ns := affected.Namespace
	if ns == "" {
		ns = "default"
	}

	r := &Remediation{
		Type:        RemediationRBAC,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, ns, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "ServiceAccount",
			Name:      "default",
			Namespace: ns,
		},
		Action: "Create dedicated service account for workload",
	}

	saName := "app-service-account"

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: "Create dedicated service account",
			YAML: fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
automountServiceAccountToken: false`, saName, ns),
		},
	}

	return r
}

func remediateAutoMountToken(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	ns := affected.Namespace
	if ns == "" {
		ns = "default"
	}

	r := &Remediation{
		Type:        RemediationServiceAccount,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, ns, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      "ServiceAccount",
			Name:      affected.Name,
			Namespace: ns,
		},
		Action: "Disable automatic token mounting",
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Disable automountServiceAccountToken on service account",
			YAML: fmt.Sprintf(`apiVersion: v1
kind: ServiceAccount
metadata:
  name: %s
  namespace: %s
automountServiceAccountToken: false`, affected.Name, ns),
		},
	}

	return r
}

func remediatePodCreateAccess(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	r := &Remediation{
		Type:        RemediationRBAC,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Remove pod creation permissions",
	}

	roleName := affected.Name + "-no-pod-create"
	var yaml string

	if affected.Kind == "ClusterRole" || affected.Namespace == "" {
		yaml = fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: ClusterRole
metadata:
  name: %s
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get", "list"]`, roleName)
	} else {
		yaml = fmt.Sprintf(`apiVersion: rbac.authorization.k8s.io/v1
kind: Role
metadata:
  name: %s
  namespace: %s
rules:
- apiGroups: [""]
  resources: ["pods"]
  verbs: ["get", "list", "watch"]
- apiGroups: [""]
  resources: ["pods/log"]
  verbs: ["get", "list"]`, roleName, affected.Namespace)
	}

	r.Manifests = []Manifest{
		{
			Action:      "create",
			Description: "Create role without pod creation permissions",
			YAML:        yaml,
		},
	}

	return r
}

func remediateEscalationPermissions(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	r := &Remediation{
		Type:        RemediationRBAC,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Remove escalation permissions (bind/escalate/impersonate)",
	}

	r.Manifests = []Manifest{
		{
			Action:      "review",
			Description: "Review and remove bind, escalate, or impersonate verbs from role",
			YAML: fmt.Sprintf(`# Review %s %s and remove dangerous verbs:
# - bind (on roles/clusterroles)
# - escalate (on roles/clusterroles)
# - impersonate (on users/groups/serviceaccounts)
#
# These permissions allow privilege escalation and should be
# restricted to cluster administrators only.`, affected.Kind, affected.Name),
		},
	}

	return r
}

func remediateNodeAccess(f analysis.RBACFinding, affected analysis.AffectedResource) *Remediation {
	r := &Remediation{
		Type:        RemediationRBAC,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Restrict node access permissions",
	}

	r.Manifests = []Manifest{
		{
			Action:      "review",
			Description: "Review and restrict node access permissions",
			YAML: fmt.Sprintf(`# Review %s %s and restrict node access:
#
# Node access should be limited to:
# - Monitoring systems (get, list, watch only)
# - Node lifecycle controllers
#
# Remove update/patch/delete on nodes unless absolutely required.`, affected.Kind, affected.Name),
		},
	}

	return r
}
