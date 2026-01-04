package analysis

import (
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

func TestRunPodSecurityAudit(t *testing.T) {
	g := graph.New()

	// Add a privileged container workload (use "prod" not "default" which is filtered as system ns)
	privilegedWorkload := &graph.Node{
		ID:        "workload:prod:privileged-deploy",
		Type:      graph.NodeWorkload,
		Name:      "privileged-deploy",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "Deployment",
			PodSecurityContext: &graph.PodSecurityContext{
				Containers: []graph.ContainerSecurityInfo{
					{
						Name:       "main",
						Privileged: true,
					},
				},
			},
		},
	}
	g.AddNode(privilegedWorkload)

	// Add a host network workload
	hostNetworkWorkload := &graph.Node{
		ID:        "workload:prod:host-net",
		Type:      graph.NodeWorkload,
		Name:      "host-net",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "Deployment",
			PodSecurityContext: &graph.PodSecurityContext{
				HostNetwork: true,
				Containers: []graph.ContainerSecurityInfo{
					{Name: "main"},
				},
			},
		},
	}
	g.AddNode(hostNetworkWorkload)

	// Run audit
	result := RunPodSecurityAudit(g, PodSecurityOptions{})

	if len(result.Findings) == 0 {
		t.Error("Expected findings for insecure workloads")
	}

	// Should find PSS001 (Privileged) and PSS002 (Host Network)
	foundPSS001 := false
	foundPSS002 := false

	for _, f := range result.Findings {
		switch f.CheckID {
		case "PSS001":
			foundPSS001 = true
			if len(f.Affected) != 1 {
				t.Errorf("PSS001 should have 1 affected workload, got %d", len(f.Affected))
			}
		case "PSS002":
			foundPSS002 = true
			if len(f.Affected) != 1 {
				t.Errorf("PSS002 should have 1 affected workload, got %d", len(f.Affected))
			}
		}
	}

	if !foundPSS001 {
		t.Error("Expected PSS001 (Privileged Containers) finding")
	}
	if !foundPSS002 {
		t.Error("Expected PSS002 (Host Network) finding")
	}
}

func TestPodSecurityAuditDangerousCapabilities(t *testing.T) {
	g := graph.New()

	workload := &graph.Node{
		ID:        "workload:prod:cap-test",
		Type:      graph.NodeWorkload,
		Name:      "cap-test",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "Deployment",
			PodSecurityContext: &graph.PodSecurityContext{
				Containers: []graph.ContainerSecurityInfo{
					{
						Name:         "main",
						Capabilities: []string{"SYS_ADMIN", "NET_ADMIN"},
					},
				},
			},
		},
	}
	g.AddNode(workload)

	result := RunPodSecurityAudit(g, PodSecurityOptions{
		ChecksToRun: []string{"PSS006"},
	})

	if len(result.Findings) == 0 {
		t.Fatal("Expected PSS006 finding for dangerous capabilities")
	}

	finding := result.Findings[0]
	if finding.CheckID != "PSS006" {
		t.Errorf("Expected PSS006, got %s", finding.CheckID)
	}

	// Should find 2 capabilities (SYS_ADMIN and NET_ADMIN)
	if len(finding.Affected) != 2 {
		t.Errorf("Expected 2 findings (one per dangerous cap), got %d", len(finding.Affected))
	}
}

func TestPodSecurityAuditHostPaths(t *testing.T) {
	g := graph.New()

	workload := &graph.Node{
		ID:        "workload:prod:hostpath-test",
		Type:      graph.NodeWorkload,
		Name:      "hostpath-test",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "DaemonSet",
			PodSecurityContext: &graph.PodSecurityContext{
				HostPaths: []string{"/var/run/docker.sock", "/etc/kubernetes"},
				Containers: []graph.ContainerSecurityInfo{
					{Name: "main"},
				},
			},
		},
	}
	g.AddNode(workload)

	result := RunPodSecurityAudit(g, PodSecurityOptions{
		ChecksToRun: []string{"PSS005"},
	})

	if len(result.Findings) == 0 {
		t.Fatal("Expected PSS005 finding for host paths")
	}

	finding := result.Findings[0]
	if finding.CheckID != "PSS005" {
		t.Errorf("Expected PSS005, got %s", finding.CheckID)
	}

	if len(finding.Affected) != 2 {
		t.Errorf("Expected 2 affected items (one per host path), got %d", len(finding.Affected))
	}
}

func TestPodSecurityAuditNamespaceFilter(t *testing.T) {
	g := graph.New()

	// Add workloads in different namespaces
	workload1 := &graph.Node{
		ID:        "workload:prod:priv-1",
		Type:      graph.NodeWorkload,
		Name:      "priv-1",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "Deployment",
			PodSecurityContext: &graph.PodSecurityContext{
				Containers: []graph.ContainerSecurityInfo{
					{Name: "main", Privileged: true},
				},
			},
		},
	}
	g.AddNode(workload1)

	workload2 := &graph.Node{
		ID:        "workload:dev:priv-2",
		Type:      graph.NodeWorkload,
		Name:      "priv-2",
		Namespace: "dev",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "Deployment",
			PodSecurityContext: &graph.PodSecurityContext{
				Containers: []graph.ContainerSecurityInfo{
					{Name: "main", Privileged: true},
				},
			},
		},
	}
	g.AddNode(workload2)

	// Filter to only prod namespace
	result := RunPodSecurityAudit(g, PodSecurityOptions{
		ChecksToRun: []string{"PSS001"},
		Namespace:   "prod",
	})

	if len(result.Findings) != 1 {
		t.Fatalf("Expected 1 finding, got %d", len(result.Findings))
	}

	finding := result.Findings[0]
	if len(finding.Affected) != 1 {
		t.Errorf("Expected 1 affected (prod only), got %d", len(finding.Affected))
	}

	if finding.Affected[0].Namespace != "prod" {
		t.Errorf("Expected namespace prod, got %s", finding.Affected[0].Namespace)
	}
}

func TestPodSecurityAuditSkipChecks(t *testing.T) {
	g := graph.New()

	workload := &graph.Node{
		ID:        "workload:prod:skip-test",
		Type:      graph.NodeWorkload,
		Name:      "skip-test",
		Namespace: "prod",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "Deployment",
			PodSecurityContext: &graph.PodSecurityContext{
				HostNetwork: true,
				HostPID:     true,
				Containers: []graph.ContainerSecurityInfo{
					{Name: "main", Privileged: true},
				},
			},
		},
	}
	g.AddNode(workload)

	// Skip PSS001 (Privileged)
	result := RunPodSecurityAudit(g, PodSecurityOptions{
		SkipChecks: []string{"PSS001"},
	})

	for _, f := range result.Findings {
		if f.CheckID == "PSS001" {
			t.Error("PSS001 should have been skipped")
		}
	}

	// Should still find PSS002 and PSS003
	foundPSS002 := false
	foundPSS003 := false
	for _, f := range result.Findings {
		if f.CheckID == "PSS002" {
			foundPSS002 = true
		}
		if f.CheckID == "PSS003" {
			foundPSS003 = true
		}
	}

	if !foundPSS002 {
		t.Error("Expected PSS002 finding (not skipped)")
	}
	if !foundPSS003 {
		t.Error("Expected PSS003 finding (not skipped)")
	}
}

func TestPodSecurityAuditSystemNamespaceExclusion(t *testing.T) {
	g := graph.New()

	// Add privileged workload in kube-system
	systemWorkload := &graph.Node{
		ID:        "workload:kube-system:kube-proxy",
		Type:      graph.NodeWorkload,
		Name:      "kube-proxy",
		Namespace: "kube-system",
		Metadata: graph.NodeMetadata{
			WorkloadKind: "DaemonSet",
			PodSecurityContext: &graph.PodSecurityContext{
				Containers: []graph.ContainerSecurityInfo{
					{Name: "main", Privileged: true},
				},
			},
		},
	}
	g.AddNode(systemWorkload)

	// Without IncludeSystem, should find no issues
	result := RunPodSecurityAudit(g, PodSecurityOptions{
		IncludeSystem: false,
		ChecksToRun:   []string{"PSS001"},
	})

	if len(result.Findings) > 0 {
		t.Error("Should not report findings for system namespace when IncludeSystem=false")
	}

	// With IncludeSystem, should find the privileged container
	resultWithSystem := RunPodSecurityAudit(g, PodSecurityOptions{
		IncludeSystem: true,
		ChecksToRun:   []string{"PSS001"},
	})

	if len(resultWithSystem.Findings) == 0 {
		t.Error("Should report findings for system namespace when IncludeSystem=true")
	}
}
