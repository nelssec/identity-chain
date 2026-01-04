package analysis

import (
	"fmt"
	"strings"

	"github.com/nelssec/identity-chain/pkg/collector"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type PodSecurityResult struct {
	Findings      []PodSecurityFinding
	Summary       PodSecuritySummary
	ChecksRun     []string
	TotalFindings int
}

type PodSecuritySummary struct {
	Critical   int
	High       int
	Medium     int
	Low        int
	ByCategory map[string]int
}

type PodSecurityFinding struct {
	CheckID     string
	Category    string
	Severity    graph.Severity
	Title       string
	Description string
	Affected    []AffectedWorkload
	Remediation string
}

type AffectedWorkload struct {
	Kind      string
	Namespace string
	Name      string
	Container string
	Details   string
}

type PodSecurityCheck struct {
	ID          string
	Name        string
	Category    string
	Severity    graph.Severity
	Description string
	Remediation string
}

var PodSecurityChecks = []PodSecurityCheck{
	{
		ID:          "PSS001",
		Name:        "Privileged Containers",
		Category:    "privilege_escalation",
		Severity:    graph.SeverityCritical,
		Description: "Containers running in privileged mode have full access to the host",
		Remediation: "Remove privileged: true from container security context",
	},
	{
		ID:          "PSS002",
		Name:        "Host Network",
		Category:    "network_exposure",
		Severity:    graph.SeverityHigh,
		Description: "Pods using host network can access all network interfaces on the node",
		Remediation: "Remove hostNetwork: true from pod spec",
	},
	{
		ID:          "PSS003",
		Name:        "Host PID",
		Category:    "privilege_escalation",
		Severity:    graph.SeverityHigh,
		Description: "Pods with host PID can see and signal all processes on the node",
		Remediation: "Remove hostPID: true from pod spec",
	},
	{
		ID:          "PSS004",
		Name:        "Host IPC",
		Category:    "privilege_escalation",
		Severity:    graph.SeverityMedium,
		Description: "Pods with host IPC can access shared memory on the node",
		Remediation: "Remove hostIPC: true from pod spec",
	},
	{
		ID:          "PSS005",
		Name:        "Host Path Volumes",
		Category:    "data_access",
		Severity:    graph.SeverityHigh,
		Description: "Pods mounting host paths can read/write host filesystem",
		Remediation: "Use persistent volumes instead of hostPath",
	},
	{
		ID:          "PSS006",
		Name:        "Dangerous Capabilities",
		Category:    "privilege_escalation",
		Severity:    graph.SeverityCritical,
		Description: "Containers with dangerous Linux capabilities can escape container isolation",
		Remediation: "Remove dangerous capabilities or use drop: [ALL]",
	},
	{
		ID:          "PSS007",
		Name:        "Running as Root",
		Category:    "privilege_escalation",
		Severity:    graph.SeverityMedium,
		Description: "Containers running as root have elevated privileges within the container",
		Remediation: "Set runAsNonRoot: true and specify runAsUser",
	},
	{
		ID:          "PSS008",
		Name:        "Allow Privilege Escalation",
		Category:    "privilege_escalation",
		Severity:    graph.SeverityHigh,
		Description: "Containers that allow privilege escalation can gain additional privileges",
		Remediation: "Set allowPrivilegeEscalation: false",
	},
	{
		ID:          "PSS009",
		Name:        "Missing Security Context",
		Category:    "misconfiguration",
		Severity:    graph.SeverityLow,
		Description: "Containers without security context rely on defaults which may be insecure",
		Remediation: "Add explicit securityContext to containers",
	},
	{
		ID:          "PSS010",
		Name:        "Writable Root Filesystem",
		Category:    "data_integrity",
		Severity:    graph.SeverityLow,
		Description: "Containers with writable root filesystem can be modified at runtime",
		Remediation: "Set readOnlyRootFilesystem: true",
	},
	{
		ID:          "PSS011",
		Name:        "Host Ports",
		Category:    "network_exposure",
		Severity:    graph.SeverityMedium,
		Description: "Containers using host ports expose services directly on node",
		Remediation: "Use NodePort or LoadBalancer services instead",
	},
	{
		ID:          "PSS012",
		Name:        "Secrets as Environment Variables",
		Category:    "secret_exposure",
		Severity:    graph.SeverityMedium,
		Description: "Secrets in environment variables can be exposed in logs and process lists",
		Remediation: "Mount secrets as files instead of environment variables",
	},
	{
		ID:          "PSS013",
		Name:        "Missing Resource Limits",
		Category:    "resource_exhaustion",
		Severity:    graph.SeverityMedium,
		Description: "Container lacks CPU/memory limits, enabling resource exhaustion attacks",
		Remediation: "Set resources.limits for CPU and memory on all containers",
	},
	{
		ID:          "PSS014",
		Name:        "Missing Resource Requests",
		Category:    "resource_exhaustion",
		Severity:    graph.SeverityLow,
		Description: "Container lacks CPU/memory requests, may affect scheduling",
		Remediation: "Set resources.requests for CPU and memory on all containers",
	},
	{
		ID:          "PSS015",
		Name:        "Service Mesh Sidecar Missing",
		Category:    "network_security",
		Severity:    graph.SeverityLow,
		Description: "Workload not enrolled in service mesh, traffic is unencrypted",
		Remediation: "Enable service mesh sidecar injection for mTLS and traffic encryption",
	},
	{
		ID:          "PSS016",
		Name:        "Default Namespace Usage",
		Category:    "misconfiguration",
		Severity:    graph.SeverityMedium,
		Description: "Workload running in default namespace",
		Remediation: "Move workloads to dedicated namespaces with proper RBAC isolation",
	},
	{
		ID:          "PSS017",
		Name:        "Image Pull Policy Always",
		Category:    "supply_chain",
		Severity:    graph.SeverityLow,
		Description: "Container using :latest tag or missing imagePullPolicy: Always",
		Remediation: "Use specific image tags and set imagePullPolicy: Always",
	},
}

var dangerousCapabilities = map[string]bool{
	"ALL":              true,
	"SYS_ADMIN":        true,
	"NET_ADMIN":        true,
	"SYS_PTRACE":       true,
	"SYS_MODULE":       true,
	"DAC_OVERRIDE":     true,
	"DAC_READ_SEARCH":  true,
	"NET_RAW":          true,
	"SYS_RAWIO":        true,
	"MKNOD":            true,
	"SETUID":           true,
	"SETGID":           true,
	"SYS_CHROOT":       true,
	"AUDIT_WRITE":      true,
	"SETFCAP":          true,
	"MAC_ADMIN":        true,
	"MAC_OVERRIDE":     true,
	"BPF":              true,
	"PERFMON":          true,
	"CAP_SYS_BOOT":     true,
	"CAP_SYS_TIME":     true,
	"CAP_LINUX_IMMUTABLE": true,
}

var sensitiveHostPaths = map[string]string{
	"/":                    "root filesystem",
	"/etc":                 "system configuration",
	"/var/run/docker.sock": "Docker socket",
	"/var/run/crio":        "CRI-O socket",
	"/var/run/containerd":  "containerd socket",
	"/var/lib/kubelet":     "kubelet data",
	"/etc/kubernetes":      "Kubernetes configuration",
	"/root":                "root home directory",
	"/home":                "user home directories",
	"/proc":                "process filesystem",
	"/sys":                 "system filesystem",
	"/dev":                 "device filesystem",
}

type PodSecurityOptions struct {
	ChecksToRun   []string
	SkipChecks    []string
	IncludeSystem bool
	Namespace     string
}

func RunPodSecurityAudit(g *graph.Graph, opts PodSecurityOptions) *PodSecurityResult {
	result := &PodSecurityResult{
		ChecksRun: make([]string, 0),
		Summary: PodSecuritySummary{
			ByCategory: make(map[string]int),
		},
	}

	checksToRun := make(map[string]bool)
	if len(opts.ChecksToRun) > 0 {
		for _, c := range opts.ChecksToRun {
			checksToRun[c] = true
		}
	} else {
		for _, c := range PodSecurityChecks {
			checksToRun[c.ID] = true
		}
	}

	for _, skip := range opts.SkipChecks {
		delete(checksToRun, skip)
	}

	workloads := g.GetNodesByType(graph.NodeWorkload)

	for _, check := range PodSecurityChecks {
		if !checksToRun[check.ID] {
			continue
		}

		result.ChecksRun = append(result.ChecksRun, check.ID)

		var affected []AffectedWorkload

		for _, workload := range workloads {
			if !opts.IncludeSystem && collector.IsSystemNamespace(workload.Namespace) {
				continue
			}
			if opts.Namespace != "" && workload.Namespace != opts.Namespace {
				continue
			}

			findings := checkWorkloadSecurity(workload, check)
			affected = append(affected, findings...)
		}

		if len(affected) > 0 {
			finding := PodSecurityFinding{
				CheckID:     check.ID,
				Category:    check.Category,
				Severity:    check.Severity,
				Title:       check.Name,
				Description: check.Description,
				Affected:    affected,
				Remediation: check.Remediation,
			}
			result.Findings = append(result.Findings, finding)
			result.TotalFindings += len(affected)

			switch check.Severity {
			case graph.SeverityCritical:
				result.Summary.Critical++
			case graph.SeverityHigh:
				result.Summary.High++
			case graph.SeverityMedium:
				result.Summary.Medium++
			case graph.SeverityLow:
				result.Summary.Low++
			}

			result.Summary.ByCategory[check.Category] += len(affected)
		}
	}

	sortFindingsBySeverity(result.Findings)
	return result
}

func checkWorkloadSecurity(workload *graph.Node, check PodSecurityCheck) []AffectedWorkload {
	var affected []AffectedWorkload

	switch check.ID {
	case "PSS001":
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if c.Privileged {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   "Container runs in privileged mode",
					})
				}
			}
		}

	case "PSS002":
		if workload.Metadata.PodSecurityContext != nil && workload.Metadata.PodSecurityContext.HostNetwork {
			affected = append(affected, AffectedWorkload{
				Kind:      workload.Metadata.WorkloadKind,
				Namespace: workload.Namespace,
				Name:      workload.Name,
				Details:   "Pod uses host network",
			})
		}

	case "PSS003":
		if workload.Metadata.PodSecurityContext != nil && workload.Metadata.PodSecurityContext.HostPID {
			affected = append(affected, AffectedWorkload{
				Kind:      workload.Metadata.WorkloadKind,
				Namespace: workload.Namespace,
				Name:      workload.Name,
				Details:   "Pod uses host PID namespace",
			})
		}

	case "PSS004":
		if workload.Metadata.PodSecurityContext != nil && workload.Metadata.PodSecurityContext.HostIPC {
			affected = append(affected, AffectedWorkload{
				Kind:      workload.Metadata.WorkloadKind,
				Namespace: workload.Namespace,
				Name:      workload.Name,
				Details:   "Pod uses host IPC namespace",
			})
		}

	case "PSS005":
		if workload.Metadata.PodSecurityContext != nil {
			for _, hp := range workload.Metadata.PodSecurityContext.HostPaths {
				desc := "mounts host path"
				if reason, sensitive := isSensitiveHostPath(hp); sensitive {
					desc = fmt.Sprintf("mounts sensitive host path (%s)", reason)
				}
				affected = append(affected, AffectedWorkload{
					Kind:      workload.Metadata.WorkloadKind,
					Namespace: workload.Namespace,
					Name:      workload.Name,
					Details:   fmt.Sprintf("%s: %s", desc, hp),
				})
			}
		}

	case "PSS006":
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				for _, cap := range c.Capabilities {
					if dangerousCapabilities[strings.ToUpper(cap)] {
						affected = append(affected, AffectedWorkload{
							Kind:      workload.Metadata.WorkloadKind,
							Namespace: workload.Namespace,
							Name:      workload.Name,
							Container: c.Name,
							Details:   fmt.Sprintf("Has dangerous capability: %s", cap),
						})
					}
				}
			}
		}

	case "PSS007":
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if c.RunAsRoot {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   "Container runs as root",
					})
				}
			}
		}

	case "PSS008":
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if c.AllowPrivilegeEscalation {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   "Container allows privilege escalation",
					})
				}
			}
		}

	case "PSS009":
		if workload.Metadata.PodSecurityContext == nil {
			affected = append(affected, AffectedWorkload{
				Kind:      workload.Metadata.WorkloadKind,
				Namespace: workload.Namespace,
				Name:      workload.Name,
				Details:   "No security context defined",
			})
		} else {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if !c.HasSecurityContext {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   "Container has no security context",
					})
				}
			}
		}

	case "PSS010":
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if !c.ReadOnlyRootFilesystem {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   "Container has writable root filesystem",
					})
				}
			}
		}

	case "PSS011":
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				for _, port := range c.HostPorts {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   fmt.Sprintf("Uses host port %d", port),
					})
				}
			}
		}

	case "PSS012":
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if c.SecretsInEnv > 0 {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   fmt.Sprintf("%d secrets exposed as environment variables", c.SecretsInEnv),
					})
				}
			}
		}

	case "PSS013":
		// Missing resource limits
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if !c.HasResourceLimits {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   "Container missing CPU/memory limits",
					})
				}
			}
		}

	case "PSS014":
		// Missing resource requests
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if !c.HasResourceRequests {
					affected = append(affected, AffectedWorkload{
						Kind:      workload.Metadata.WorkloadKind,
						Namespace: workload.Namespace,
						Name:      workload.Name,
						Container: c.Name,
						Details:   "Container missing CPU/memory requests",
					})
				}
			}
		}

	case "PSS015":
		// Service mesh sidecar missing - check for common sidecar containers
		hasSidecar := false
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				// Check for common service mesh sidecars
				if c.Name == "istio-proxy" || c.Name == "envoy" || c.Name == "linkerd-proxy" {
					hasSidecar = true
					break
				}
			}
		}
		// Also check for annotations indicating mesh enrollment
		if workload.Labels != nil {
			if _, ok := workload.Labels["sidecar.istio.io/inject"]; ok {
				hasSidecar = true
			}
		}
		if !hasSidecar && !collector.IsSystemNamespace(workload.Namespace) {
			affected = append(affected, AffectedWorkload{
				Kind:      workload.Metadata.WorkloadKind,
				Namespace: workload.Namespace,
				Name:      workload.Name,
				Details:   "No service mesh sidecar detected",
			})
		}

	case "PSS016":
		// Default namespace usage
		if workload.Namespace == "default" {
			affected = append(affected, AffectedWorkload{
				Kind:      workload.Metadata.WorkloadKind,
				Namespace: workload.Namespace,
				Name:      workload.Name,
				Details:   "Workload running in default namespace",
			})
		}

	case "PSS017":
		// Image pull policy check
		if workload.Metadata.PodSecurityContext != nil {
			for _, c := range workload.Metadata.PodSecurityContext.Containers {
				if c.ImagePullPolicy != "Always" {
					// Check if using :latest tag
					if strings.HasSuffix(c.Image, ":latest") || !strings.Contains(c.Image, ":") {
						affected = append(affected, AffectedWorkload{
							Kind:      workload.Metadata.WorkloadKind,
							Namespace: workload.Namespace,
							Name:      workload.Name,
							Container: c.Name,
							Details:   fmt.Sprintf("Using image %s without pullPolicy: Always", c.Image),
						})
					}
				}
			}
		}
	}

	return affected
}

func isSensitiveHostPath(path string) (string, bool) {
	for sensitivePath, reason := range sensitiveHostPaths {
		if path == sensitivePath || strings.HasPrefix(path, sensitivePath+"/") {
			return reason, true
		}
	}
	return "", false
}

func sortFindingsBySeverity(findings []PodSecurityFinding) {
	severityOrder := map[graph.Severity]int{
		graph.SeverityCritical: 0,
		graph.SeverityHigh:     1,
		graph.SeverityMedium:   2,
		graph.SeverityLow:      3,
	}

	for i := 0; i < len(findings); i++ {
		for j := i + 1; j < len(findings); j++ {
			if severityOrder[findings[i].Severity] > severityOrder[findings[j].Severity] {
				findings[i], findings[j] = findings[j], findings[i]
			}
		}
	}
}
