package analysis

type CISControl struct {
	ID          string
	Section     string
	Title       string
	Description string
	Level       int
	Scored      bool
}

type CISMapping struct {
	CheckID    string
	CISControl CISControl
}

var CISBenchmarkV18 = map[string]CISControl{
	"5.1.1": {
		ID:          "5.1.1",
		Section:     "RBAC and Service Accounts",
		Title:       "Ensure that the cluster-admin role is only used where required",
		Description: "The RBAC role cluster-admin provides wide-ranging powers over the environment and should be used only where and when needed.",
		Level:       1,
		Scored:      false,
	},
	"5.1.2": {
		ID:          "5.1.2",
		Section:     "RBAC and Service Accounts",
		Title:       "Minimize access to secrets",
		Description: "The Kubernetes API stores secrets, which may be service account tokens for the Kubernetes API or credentials used by workloads.",
		Level:       1,
		Scored:      false,
	},
	"5.1.3": {
		ID:          "5.1.3",
		Section:     "RBAC and Service Accounts",
		Title:       "Minimize wildcard use in Roles and ClusterRoles",
		Description: "Kubernetes Roles and ClusterRoles provide access to resources based on sets of objects and actions that can be taken on those objects.",
		Level:       1,
		Scored:      false,
	},
	"5.1.4": {
		ID:          "5.1.4",
		Section:     "RBAC and Service Accounts",
		Title:       "Minimize access to create pods",
		Description: "The ability to create pods in a namespace can provide a number of opportunities for privilege escalation.",
		Level:       1,
		Scored:      false,
	},
	"5.1.5": {
		ID:          "5.1.5",
		Section:     "RBAC and Service Accounts",
		Title:       "Ensure that default service accounts are not actively used",
		Description: "The default service account should not be used to ensure that rights granted to applications can be more easily audited.",
		Level:       1,
		Scored:      true,
	},
	"5.1.6": {
		ID:          "5.1.6",
		Section:     "RBAC and Service Accounts",
		Title:       "Ensure that Service Account Tokens are only mounted where necessary",
		Description: "Service accounts tokens should not be mounted in pods except where the workload running in the pod explicitly needs to communicate with the API server.",
		Level:       1,
		Scored:      false,
	},
	"5.1.8": {
		ID:          "5.1.8",
		Section:     "RBAC and Service Accounts",
		Title:       "Limit use of the Bind, Impersonate and Escalate permissions in the Kubernetes cluster",
		Description: "Cluster roles and roles with the impersonate, bind or escalate permissions should not be granted unless strictly required.",
		Level:       1,
		Scored:      false,
	},
	"5.2.1": {
		ID:          "5.2.1",
		Section:     "Pod Security Standards",
		Title:       "Ensure that the cluster has at least one active policy control mechanism in place",
		Description: "Every Kubernetes cluster should have at least one policy control mechanism in place to enforce the Baseline or Restricted policies.",
		Level:       1,
		Scored:      false,
	},
	"5.2.2": {
		ID:          "5.2.2",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of privileged containers",
		Description: "Do not generally permit containers to be run with the securityContext.privileged flag set to true.",
		Level:       1,
		Scored:      false,
	},
	"5.2.3": {
		ID:          "5.2.3",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of containers wishing to share the host process ID namespace",
		Description: "Do not generally permit containers to be run with the hostPID flag set to true.",
		Level:       1,
		Scored:      false,
	},
	"5.2.4": {
		ID:          "5.2.4",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of containers wishing to share the host IPC namespace",
		Description: "Do not generally permit containers to be run with the hostIPC flag set to true.",
		Level:       1,
		Scored:      false,
	},
	"5.2.5": {
		ID:          "5.2.5",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of containers wishing to share the host network namespace",
		Description: "Do not generally permit containers to be run with the hostNetwork flag set to true.",
		Level:       1,
		Scored:      false,
	},
	"5.2.6": {
		ID:          "5.2.6",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of containers with allowPrivilegeEscalation",
		Description: "Do not generally permit containers to be run with the allowPrivilegeEscalation flag set to true.",
		Level:       1,
		Scored:      false,
	},
	"5.2.7": {
		ID:          "5.2.7",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of root containers",
		Description: "Do not generally permit containers to be run as the root user.",
		Level:       2,
		Scored:      false,
	},
	"5.2.8": {
		ID:          "5.2.8",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of containers with the NET_RAW capability",
		Description: "Do not generally permit containers with the potentially dangerous NET_RAW capability.",
		Level:       1,
		Scored:      false,
	},
	"5.2.9": {
		ID:          "5.2.9",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of containers with added capabilities",
		Description: "Do not generally permit containers with capabilities assigned beyond the default set.",
		Level:       1,
		Scored:      false,
	},
	"5.2.10": {
		ID:          "5.2.10",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of containers with capabilities assigned",
		Description: "Do not generally permit containers with capabilities.",
		Level:       2,
		Scored:      false,
	},
	"5.2.11": {
		ID:          "5.2.11",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of Windows HostProcess containers",
		Description: "Do not generally permit Windows containers to be run with the hostProcess flag set to true.",
		Level:       1,
		Scored:      false,
	},
	"5.2.12": {
		ID:          "5.2.12",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of HostPath volumes",
		Description: "Do not generally permit containers to be run with the hostPath volume.",
		Level:       1,
		Scored:      false,
	},
	"5.2.13": {
		ID:          "5.2.13",
		Section:     "Pod Security Standards",
		Title:       "Minimize the admission of containers which use HostPorts",
		Description: "Do not generally permit containers which require the use of HostPorts.",
		Level:       1,
		Scored:      false,
	},
	"5.3.1": {
		ID:          "5.3.1",
		Section:     "Network Policies and CNI",
		Title:       "Ensure that the CNI in use supports NetworkPolicies",
		Description: "There are a variety of CNI plugins available for Kubernetes. If the CNI in use does not support Network Policies it may not be possible to effectively restrict traffic in the cluster.",
		Level:       1,
		Scored:      false,
	},
	"5.3.2": {
		ID:          "5.3.2",
		Section:     "Network Policies and CNI",
		Title:       "Ensure that all Namespaces have NetworkPolicies defined",
		Description: "Use network policies to isolate traffic in your cluster network.",
		Level:       2,
		Scored:      true,
	},
	"5.7.1": {
		ID:          "5.7.1",
		Section:     "General Policies",
		Title:       "Create administrative boundaries between resources using namespaces",
		Description: "Use namespaces to isolate your Kubernetes objects.",
		Level:       1,
		Scored:      false,
	},
	"5.7.2": {
		ID:          "5.7.2",
		Section:     "General Policies",
		Title:       "Ensure that the seccomp profile is set to docker/default in your pod definitions",
		Description: "Enable docker/default seccomp profile in your pod definitions.",
		Level:       2,
		Scored:      false,
	},
	"5.7.3": {
		ID:          "5.7.3",
		Section:     "General Policies",
		Title:       "Apply Security Context to Your Pods and Containers",
		Description: "Apply Security Context to Your Pods and Containers.",
		Level:       2,
		Scored:      false,
	},
	"5.7.4": {
		ID:          "5.7.4",
		Section:     "General Policies",
		Title:       "The default namespace should not be used",
		Description: "Resources in the default namespace cannot be isolated by policy.",
		Level:       2,
		Scored:      true,
	},
}

var CheckToCISMapping = map[string][]string{
	"RBAC001": {"5.1.1"},
	"RBAC002": {"5.1.1"},
	"RBAC003": {"5.1.2"},
	"RBAC004": {"5.1.3"},
	"RBAC005": {"5.1.5"},
	"RBAC006": {"5.1.6"},
	"RBAC007": {"5.1.4"},
	"RBAC008": {"5.1.8"},
	"RBAC009": {"5.1.8"},
	"RBAC010": {"5.1.8"},
	"RBAC011": {"5.1.8"},
	"RBAC012": {"5.1.2"},
	"RBAC013": {"5.1.8"},
	"RBAC014": {"5.1.8"},
	"RBAC015": {"5.1.3"},

	"PSS001": {"5.2.2"},
	"PSS002": {"5.2.5"},
	"PSS003": {"5.2.3"},
	"PSS004": {"5.2.4"},
	"PSS005": {"5.2.12"},
	"PSS006": {"5.2.9", "5.2.10"},
	"PSS007": {"5.2.6"},
	"PSS008": {"5.2.7"},
	"PSS009": {"5.2.7"},
	"PSS010": {"5.7.2"},
	"PSS011": {"5.7.2"},
	"PSS012": {"5.7.3"},
	"PSS013": {"5.7.3"},
	"PSS014": {"5.2.13"},
	"PSS015": {"5.2.9"},
	"PSS016": {"5.2.8"},
	"PSS017": {"5.2.11"},

	"NET001": {"5.3.2"},
	"NET002": {"5.3.2"},
	"NET003": {"5.3.2"},
	"NET004": {"5.3.2"},
	"NET005": {"5.3.2"},
	"NET006": {"5.3.2"},
	"NET007": {"5.3.2"},
	"NET008": {"5.3.2"},
}

func GetCISControlsForCheck(checkID string) []CISControl {
	cisIDs, ok := CheckToCISMapping[checkID]
	if !ok {
		return nil
	}

	var controls []CISControl
	for _, cisID := range cisIDs {
		if control, ok := CISBenchmarkV18[cisID]; ok {
			controls = append(controls, control)
		}
	}
	return controls
}

func GetCISIDsForCheck(checkID string) []string {
	return CheckToCISMapping[checkID]
}

type CISComplianceSummary struct {
	TotalControls   int
	PassedControls  int
	FailedControls  int
	ControlStatus   map[string]string
	FailedBySection map[string]int
}

func GenerateCISComplianceSummary(rbacFindings []RBACFinding, podSecFindings []PodSecurityFinding, netPolFindings []NetworkPolicyFinding) *CISComplianceSummary {
	summary := &CISComplianceSummary{
		ControlStatus:   make(map[string]string),
		FailedBySection: make(map[string]int),
	}

	failedControls := make(map[string]bool)

	for _, f := range rbacFindings {
		for _, cisID := range GetCISIDsForCheck(f.CheckID) {
			failedControls[cisID] = true
			if control, ok := CISBenchmarkV18[cisID]; ok {
				summary.FailedBySection[control.Section]++
			}
		}
	}

	for _, f := range podSecFindings {
		for _, cisID := range GetCISIDsForCheck(f.CheckID) {
			failedControls[cisID] = true
			if control, ok := CISBenchmarkV18[cisID]; ok {
				summary.FailedBySection[control.Section]++
			}
		}
	}

	for _, f := range netPolFindings {
		for _, cisID := range GetCISIDsForCheck(f.CheckID) {
			failedControls[cisID] = true
			if control, ok := CISBenchmarkV18[cisID]; ok {
				summary.FailedBySection[control.Section]++
			}
		}
	}

	for cisID := range CISBenchmarkV18 {
		summary.TotalControls++
		if failedControls[cisID] {
			summary.ControlStatus[cisID] = "FAIL"
			summary.FailedControls++
		} else {
			summary.ControlStatus[cisID] = "PASS"
			summary.PassedControls++
		}
	}

	return summary
}
