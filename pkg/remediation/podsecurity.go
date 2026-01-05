package remediation

import (
	"fmt"
	"strings"

	"github.com/nelssec/identity-chain/pkg/analysis"
)

func GeneratePodSecurityRemediations(findings []analysis.PodSecurityFinding) []Remediation {
	var remediations []Remediation

	for _, f := range findings {
		rems := generatePodSecurityRemediation(f)
		remediations = append(remediations, rems...)
	}

	return remediations
}

func generatePodSecurityRemediation(f analysis.PodSecurityFinding) []Remediation {
	var remediations []Remediation

	for _, affected := range f.Affected {
		r := generatePodSecurityRemediationForAffected(f, affected)
		if r != nil {
			remediations = append(remediations, *r)
		}
	}

	return remediations
}

func generatePodSecurityRemediationForAffected(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	switch f.CheckID {
	case "PSS001":
		return remediatePrivileged(f, affected)
	case "PSS002":
		return remediateHostNetwork(f, affected)
	case "PSS003":
		return remediateHostPID(f, affected)
	case "PSS004":
		return remediateHostIPC(f, affected)
	case "PSS005":
		return remediateHostPath(f, affected)
	case "PSS006", "PSS015", "PSS016":
		return remediateCapabilities(f, affected)
	case "PSS007":
		return remediatePrivilegeEscalation(f, affected)
	case "PSS008", "PSS009":
		return remediateRunAsRoot(f, affected)
	case "PSS010", "PSS011":
		return remediateSeccomp(f, affected)
	case "PSS012", "PSS013":
		return remediateSecurityContext(f, affected)
	case "PSS014":
		return remediateHostPorts(f, affected)
	case "PSS017":
		return remediateWindowsHostProcess(f, affected)
	default:
		return nil
	}
}

func remediatePrivileged(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Remove privileged flag from container",
	}

	container := affected.Container
	if container == "" {
		container = "app"
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: fmt.Sprintf("Set privileged: false for container %s", container),
			YAML: fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: %s
  namespace: %s
spec:
  template:
    spec:
      containers:
      - name: %s
        securityContext:
          privileged: false`, getAPIVersion(affected.Kind), affected.Kind, affected.Name, affected.Namespace, container),
		},
	}

	return r
}

func remediateHostNetwork(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Disable hostNetwork",
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Remove hostNetwork from pod spec",
			YAML: fmt.Sprintf(`# Patch %s/%s in namespace %s
# Remove or set hostNetwork: false in spec:
#
# spec:
#   hostNetwork: false`, affected.Kind, affected.Name, affected.Namespace),
		},
	}

	return r
}

func remediateHostPID(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Disable hostPID",
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Remove hostPID from pod spec",
			YAML: fmt.Sprintf(`# Patch %s/%s in namespace %s
# Remove or set hostPID: false in spec:
#
# spec:
#   hostPID: false`, affected.Kind, affected.Name, affected.Namespace),
		},
	}

	return r
}

func remediateHostIPC(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Disable hostIPC",
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Remove hostIPC from pod spec",
			YAML: fmt.Sprintf(`# Patch %s/%s in namespace %s
# Remove or set hostIPC: false in spec:
#
# spec:
#   hostIPC: false`, affected.Kind, affected.Name, affected.Namespace),
		},
	}

	return r
}

func remediateHostPath(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Replace hostPath volumes with safer alternatives",
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Replace hostPath volumes",
			YAML: fmt.Sprintf(`# Patch %s/%s in namespace %s
# Replace hostPath volumes with safer alternatives:
#
# Instead of:
#   volumes:
#   - name: host-vol
#     hostPath:
#       path: /var/log
#
# Use:
#   volumes:
#   - name: log-vol
#     emptyDir: {}
#
# Or for persistent data:
#   volumes:
#   - name: data-vol
#     persistentVolumeClaim:
#       claimName: my-pvc`, affected.Kind, affected.Name, affected.Namespace),
		},
	}

	return r
}

func remediateCapabilities(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Drop dangerous capabilities",
	}

	container := affected.Container
	if container == "" {
		container = "app"
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: fmt.Sprintf("Drop dangerous capabilities for container %s", container),
			YAML: fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: %s
  namespace: %s
spec:
  template:
    spec:
      containers:
      - name: %s
        securityContext:
          capabilities:
            drop:
            - ALL
            add: []`, getAPIVersion(affected.Kind), affected.Kind, affected.Name, affected.Namespace, container),
		},
	}

	return r
}

func remediatePrivilegeEscalation(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Disable allowPrivilegeEscalation",
	}

	container := affected.Container
	if container == "" {
		container = "app"
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: fmt.Sprintf("Set allowPrivilegeEscalation: false for container %s", container),
			YAML: fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: %s
  namespace: %s
spec:
  template:
    spec:
      containers:
      - name: %s
        securityContext:
          allowPrivilegeEscalation: false`, getAPIVersion(affected.Kind), affected.Kind, affected.Name, affected.Namespace, container),
		},
	}

	return r
}

func remediateRunAsRoot(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Configure non-root execution",
	}

	container := affected.Container
	if container == "" {
		container = "app"
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Configure runAsNonRoot and specific user ID",
			YAML: fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: %s
  namespace: %s
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        runAsUser: 1000
        runAsGroup: 1000
        fsGroup: 1000
      containers:
      - name: %s
        securityContext:
          runAsNonRoot: true
          runAsUser: 1000
          runAsGroup: 1000`, getAPIVersion(affected.Kind), affected.Kind, affected.Name, affected.Namespace, container),
		},
	}

	return r
}

func remediateSeccomp(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Enable seccomp profile",
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Add RuntimeDefault seccomp profile",
			YAML: fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: %s
  namespace: %s
spec:
  template:
    spec:
      securityContext:
        seccompProfile:
          type: RuntimeDefault`, getAPIVersion(affected.Kind), affected.Kind, affected.Name, affected.Namespace),
		},
	}

	return r
}

func remediateSecurityContext(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Add security context",
	}

	container := affected.Container
	if container == "" {
		container = "app"
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Add comprehensive security context",
			YAML: fmt.Sprintf(`apiVersion: %s
kind: %s
metadata:
  name: %s
  namespace: %s
spec:
  template:
    spec:
      securityContext:
        runAsNonRoot: true
        seccompProfile:
          type: RuntimeDefault
      containers:
      - name: %s
        securityContext:
          allowPrivilegeEscalation: false
          readOnlyRootFilesystem: true
          runAsNonRoot: true
          capabilities:
            drop:
            - ALL`, getAPIVersion(affected.Kind), affected.Kind, affected.Name, affected.Namespace, container),
		},
	}

	return r
}

func remediateHostPorts(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Remove hostPort usage",
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Replace hostPort with NodePort or LoadBalancer service",
			YAML: fmt.Sprintf(`# Instead of using hostPort in %s/%s:
#
# containers:
# - name: app
#   ports:
#   - containerPort: 8080
#     hostPort: 8080  # REMOVE THIS
#
# Use a NodePort or LoadBalancer Service:
apiVersion: v1
kind: Service
metadata:
  name: %s-service
  namespace: %s
spec:
  type: NodePort
  selector:
    app: %s
  ports:
  - port: 8080
    targetPort: 8080`, affected.Kind, affected.Name, affected.Name, affected.Namespace, affected.Name),
		},
	}

	return r
}

func remediateWindowsHostProcess(f analysis.PodSecurityFinding, affected analysis.AffectedWorkload) *Remediation {
	r := &Remediation{
		Type:        RemediationPodSecurity,
		FindingID:   fmt.Sprintf("%s-%s-%s", f.CheckID, affected.Namespace, affected.Name),
		CheckID:     f.CheckID,
		Severity:    string(f.Severity),
		Description: f.Description,
		Resource: ResourceRef{
			Kind:      affected.Kind,
			Name:      affected.Name,
			Namespace: affected.Namespace,
		},
		Action: "Disable Windows HostProcess",
	}

	r.Manifests = []Manifest{
		{
			Action:      "patch",
			Description: "Remove hostProcess from Windows security options",
			YAML: fmt.Sprintf(`# Patch %s/%s in namespace %s
# Remove or set hostProcess: false in securityContext:
#
# spec:
#   securityContext:
#     windowsOptions:
#       hostProcess: false`, affected.Kind, affected.Name, affected.Namespace),
		},
	}

	return r
}

func parseContainerList(containers string) []string {
	if containers == "" {
		return []string{"app"}
	}
	parts := strings.Split(containers, ",")
	var result []string
	for _, p := range parts {
		trimmed := strings.TrimSpace(p)
		if trimmed != "" {
			result = append(result, trimmed)
		}
	}
	if len(result) == 0 {
		return []string{"app"}
	}
	return result
}

func getAPIVersion(kind string) string {
	switch kind {
	case "Deployment", "ReplicaSet", "StatefulSet", "DaemonSet":
		return "apps/v1"
	case "Job":
		return "batch/v1"
	case "CronJob":
		return "batch/v1"
	case "Pod":
		return "v1"
	default:
		return "apps/v1"
	}
}
