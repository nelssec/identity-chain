package remediation

import (
	"strings"
	"testing"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestGeneratePodSecurityRemediations(t *testing.T) {
	tests := []struct {
		name          string
		findings      []analysis.PodSecurityFinding
		wantCount     int
		wantAction    string
		wantCheckID   string
		checkManifest func(t *testing.T, rems []Remediation)
	}{
		{
			name: "privileged PSS001",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:     "PSS001",
					Severity:    graph.SeverityCritical,
					Description: "Privileged container",
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "web", Container: "nginx"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Remove privileged flag from container",
			wantCheckID: "PSS001",
			checkManifest: func(t *testing.T, rems []Remediation) {
				yaml := rems[0].Manifests[0].YAML
				if !strings.Contains(yaml, "privileged: false") {
					t.Error("should set privileged: false")
				}
				if !strings.Contains(yaml, "name: nginx") {
					t.Error("should reference correct container")
				}
				if !strings.Contains(yaml, "apiVersion: apps/v1") {
					t.Error("Deployment should use apps/v1")
				}
			},
		},
		{
			name: "privileged PSS001 no container defaults to app",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS001",
					Severity: graph.SeverityCritical,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "web", Container: ""},
					},
				},
			},
			wantCount: 1,
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "name: app") {
					t.Error("empty container should default to 'app'")
				}
			},
		},
		{
			name: "hostNetwork PSS002",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:     "PSS002",
					Severity:    graph.SeverityHigh,
					Description: "hostNetwork enabled",
					Affected: []analysis.AffectedWorkload{
						{Kind: "DaemonSet", Namespace: "monitoring", Name: "agent"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Disable hostNetwork",
			wantCheckID: "PSS002",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "hostNetwork: false") {
					t.Error("should mention hostNetwork: false")
				}
			},
		},
		{
			name: "hostPID PSS003",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS003",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "debug-pod"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Disable hostPID",
			wantCheckID: "PSS003",
		},
		{
			name: "hostIPC PSS004",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS004",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "ipc-pod"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Disable hostIPC",
			wantCheckID: "PSS004",
		},
		{
			name: "hostPath PSS005",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS005",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "DaemonSet", Namespace: "logging", Name: "filebeat"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Replace hostPath volumes with safer alternatives",
			wantCheckID: "PSS005",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "emptyDir") {
					t.Error("should suggest emptyDir alternative")
				}
			},
		},
		{
			name: "capabilities PSS006",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS006",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "caps-app", Container: "main"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Drop dangerous capabilities",
			wantCheckID: "PSS006",
			checkManifest: func(t *testing.T, rems []Remediation) {
				yaml := rems[0].Manifests[0].YAML
				if !strings.Contains(yaml, "drop:\n            - ALL") {
					t.Error("should drop ALL capabilities")
				}
			},
		},
		{
			name: "capabilities PSS015 and PSS016",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS015",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "a"},
					},
				},
				{
					CheckID:  "PSS016",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "b"},
					},
				},
			},
			wantCount: 2,
		},
		{
			name: "privilege escalation PSS007",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS007",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "esc-app", Container: "svc"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Disable allowPrivilegeEscalation",
			wantCheckID: "PSS007",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "allowPrivilegeEscalation: false") {
					t.Error("should set allowPrivilegeEscalation: false")
				}
			},
		},
		{
			name: "runAsRoot PSS008",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS008",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "StatefulSet", Namespace: "db", Name: "postgres", Container: "pg"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Configure non-root execution",
			wantCheckID: "PSS008",
			checkManifest: func(t *testing.T, rems []Remediation) {
				yaml := rems[0].Manifests[0].YAML
				if !strings.Contains(yaml, "runAsNonRoot: true") {
					t.Error("should set runAsNonRoot: true")
				}
				if !strings.Contains(yaml, "runAsUser: 1000") {
					t.Error("should set runAsUser: 1000")
				}
				if !strings.Contains(yaml, "apiVersion: apps/v1") {
					t.Error("StatefulSet should use apps/v1")
				}
			},
		},
		{
			name: "runAsRoot PSS009",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS009",
					Severity: graph.SeverityHigh,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "root-app"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Configure non-root execution",
			wantCheckID: "PSS009",
		},
		{
			name: "seccomp PSS010",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS010",
					Severity: graph.SeverityMedium,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "no-seccomp"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Enable seccomp profile",
			wantCheckID: "PSS010",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "RuntimeDefault") {
					t.Error("should set RuntimeDefault seccomp profile")
				}
			},
		},
		{
			name: "seccomp PSS011",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS011",
					Severity: graph.SeverityMedium,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "bad-seccomp"},
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "security context PSS012",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS012",
					Severity: graph.SeverityMedium,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "no-ctx", Container: "web"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Add security context",
			wantCheckID: "PSS012",
			checkManifest: func(t *testing.T, rems []Remediation) {
				yaml := rems[0].Manifests[0].YAML
				if !strings.Contains(yaml, "readOnlyRootFilesystem: true") {
					t.Error("should set readOnlyRootFilesystem")
				}
				if !strings.Contains(yaml, "runAsNonRoot: true") {
					t.Error("should set runAsNonRoot")
				}
			},
		},
		{
			name: "security context PSS013",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS013",
					Severity: graph.SeverityMedium,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "no-ctx2"},
					},
				},
			},
			wantCount: 1,
		},
		{
			name: "host ports PSS014",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS014",
					Severity: graph.SeverityMedium,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "port-app"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Remove hostPort usage",
			wantCheckID: "PSS014",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "kind: Service") {
					t.Error("should suggest Service as alternative")
				}
			},
		},
		{
			name: "windows host process PSS017",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS017",
					Severity: graph.SeverityCritical,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "windows", Name: "win-app"},
					},
				},
			},
			wantCount:   1,
			wantAction:  "Disable Windows HostProcess",
			wantCheckID: "PSS017",
			checkManifest: func(t *testing.T, rems []Remediation) {
				if !strings.Contains(rems[0].Manifests[0].YAML, "hostProcess: false") {
					t.Error("should set hostProcess: false")
				}
			},
		},
		{
			name: "unknown check returns nil",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS999",
					Severity: graph.SeverityLow,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "default", Name: "unknown"},
					},
				},
			},
			wantCount: 0,
		},
		{
			name:      "empty findings",
			findings:  nil,
			wantCount: 0,
		},
		{
			name: "multiple affected workloads",
			findings: []analysis.PodSecurityFinding{
				{
					CheckID:  "PSS001",
					Severity: graph.SeverityCritical,
					Affected: []analysis.AffectedWorkload{
						{Kind: "Deployment", Namespace: "ns1", Name: "app1", Container: "c1"},
						{Kind: "Deployment", Namespace: "ns2", Name: "app2", Container: "c2"},
					},
				},
			},
			wantCount: 2,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			rems := GeneratePodSecurityRemediations(tt.findings)

			if len(rems) != tt.wantCount {
				t.Fatalf("got %d remediations, want %d", len(rems), tt.wantCount)
			}

			if tt.wantCount == 0 {
				return
			}

			r := rems[0]
			if r.Type != RemediationPodSecurity {
				t.Errorf("type = %q, want %q", r.Type, RemediationPodSecurity)
			}
			if tt.wantAction != "" && r.Action != tt.wantAction {
				t.Errorf("action = %q, want %q", r.Action, tt.wantAction)
			}
			if tt.wantCheckID != "" && r.CheckID != tt.wantCheckID {
				t.Errorf("checkID = %q, want %q", r.CheckID, tt.wantCheckID)
			}
			if len(r.Manifests) == 0 {
				t.Error("expected at least one manifest")
			}
			for _, m := range r.Manifests {
				if m.YAML == "" {
					t.Error("manifest YAML should not be empty")
				}
			}

			if tt.checkManifest != nil {
				tt.checkManifest(t, rems)
			}
		})
	}
}

func TestParseContainerList(t *testing.T) {
	tests := []struct {
		name  string
		input string
		want  []string
	}{
		{"empty string returns app", "", []string{"app"}},
		{"single container", "nginx", []string{"nginx"}},
		{"multiple containers", "nginx, sidecar, init", []string{"nginx", "sidecar", "init"}},
		{"whitespace only entries filtered", "nginx,  , sidecar", []string{"nginx", "sidecar"}},
		{"all whitespace returns app", " , , ", []string{"app"}},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseContainerList(tt.input)
			if len(got) != len(tt.want) {
				t.Fatalf("parseContainerList(%q) = %v, want %v", tt.input, got, tt.want)
			}
			for i, v := range got {
				if v != tt.want[i] {
					t.Errorf("parseContainerList(%q)[%d] = %q, want %q", tt.input, i, v, tt.want[i])
				}
			}
		})
	}
}

func TestGetAPIVersion(t *testing.T) {
	tests := []struct {
		kind string
		want string
	}{
		{"Deployment", "apps/v1"},
		{"ReplicaSet", "apps/v1"},
		{"StatefulSet", "apps/v1"},
		{"DaemonSet", "apps/v1"},
		{"Job", "batch/v1"},
		{"CronJob", "batch/v1"},
		{"Pod", "v1"},
		{"Unknown", "apps/v1"},
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got := getAPIVersion(tt.kind)
			if got != tt.want {
				t.Errorf("getAPIVersion(%q) = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}
