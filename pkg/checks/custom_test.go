package checks

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

func boolPtr(b bool) *bool { return &b }
func intPtr(i int) *int    { return &i }

// buildTestGraph creates a graph with several node types for use across tests.
func buildTestGraph() *graph.Graph {
	g := graph.New()

	// ServiceAccount: default/my-sa (has cloud identity)
	sa := graph.NewNode(graph.NodeServiceAccount, "default", "my-sa")
	sa.Labels["app"] = "web"
	sa.Labels["env"] = "prod"
	sa.Metadata.CloudRoleARN = "arn:aws:iam::123456789012:role/my-role"
	_ = g.AddNode(sa)

	// ServiceAccount: kube-system/system-sa (no cloud identity, different namespace)
	saSys := graph.NewNode(graph.NodeServiceAccount, "kube-system", "system-sa")
	saSys.Labels["component"] = "controller"
	_ = g.AddNode(saSys)

	// Workload: default/web-deploy (privileged, hostNetwork)
	wl := graph.NewNode(graph.NodeWorkload, "default", "web-deploy")
	wl.Labels["app"] = "web"
	wl.Metadata.PodSecurityContext = &graph.PodSecurityContext{
		HostNetwork: true,
		HostPID:     false,
		HostIPC:     false,
		HostPaths:   []string{"/var/run/docker.sock"},
		Containers: []graph.ContainerSecurityInfo{
			{
				Name:                     "main",
				Privileged:               true,
				RunAsRoot:                true,
				AllowPrivilegeEscalation: true,
				Capabilities:             []string{"NET_ADMIN", "SYS_PTRACE"},
				HasSecurityContext:       true,
				ReadOnlyRootFilesystem:   true,
			},
		},
	}
	_ = g.AddNode(wl)

	// Workload: default/safe-deploy (not privileged, no security context)
	wlSafe := graph.NewNode(graph.NodeWorkload, "default", "safe-deploy")
	wlSafe.Labels["app"] = "api"
	_ = g.AddNode(wlSafe)

	// Role: cluster-admin (cluster role)
	role := graph.NewNode(graph.NodeRole, "", "cluster-admin")
	role.Metadata.IsClusterRole = true
	_ = g.AddNode(role)

	// Role: default/my-role (namespace role)
	nsRole := graph.NewNode(graph.NodeRole, "default", "my-role")
	_ = g.AddNode(nsRole)

	// CloudRole
	cr := graph.NewNode(graph.NodeCloudRole, "", "my-cloud-role")
	_ = g.AddNode(cr)

	// Edge: sa -> role (binds)
	bindEdge := graph.NewEdge(graph.EdgeBinds, sa.ID, role.ID)
	_ = g.AddEdge(bindEdge)

	return g
}

// writeTempYAML writes content to a temp YAML file and returns its path.
func writeTempYAML(t *testing.T, content string) string {
	t.Helper()
	dir := t.TempDir()
	path := filepath.Join(dir, "checks.yaml")
	if err := os.WriteFile(path, []byte(content), 0644); err != nil {
		t.Fatalf("failed to write temp YAML: %v", err)
	}
	return path
}

// ---------------------------------------------------------------------------
// LoadCustomChecks
// ---------------------------------------------------------------------------

func TestLoadCustomChecks(t *testing.T) {
	tests := []struct {
		name    string
		yaml    string
		file    bool // if false, use a non-existent path
		wantErr bool
		errMsg  string
		nChecks int
	}{
		{
			name: "valid config",
			yaml: `checks:
  - id: TEST001
    name: Test check
    severity: high
    category: security
    description: A test check
    match:
      kind: ServiceAccount
    condition:
      exists: true
`,
			file:    true,
			nChecks: 1,
		},
		{
			name: "multiple checks",
			yaml: `checks:
  - id: TEST001
    name: First
    match:
      kind: Workload
    condition:
      exists: true
  - id: TEST002
    name: Second
    match:
      kind: Role
    condition:
      isClusterRole: true
`,
			file:    true,
			nChecks: 2,
		},
		{
			name:    "non-existent file",
			file:    false,
			wantErr: true,
			errMsg:  "failed to read config file",
		},
		{
			name:    "invalid yaml",
			yaml:    `{{{{not yaml`,
			file:    true,
			wantErr: true,
			errMsg:  "failed to parse config",
		},
		{
			name: "missing id",
			yaml: `checks:
  - name: No ID
    match:
      kind: Workload
    condition:
      exists: true
`,
			file:    true,
			wantErr: true,
			errMsg:  "missing id",
		},
		{
			name: "missing name",
			yaml: `checks:
  - id: TEST001
    match:
      kind: Workload
    condition:
      exists: true
`,
			file:    true,
			wantErr: true,
			errMsg:  "missing name",
		},
		{
			name: "missing kind",
			yaml: `checks:
  - id: TEST001
    name: No Kind
    match: {}
    condition:
      exists: true
`,
			file:    true,
			wantErr: true,
			errMsg:  "missing match.kind",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var path string
			if tt.file {
				path = writeTempYAML(t, tt.yaml)
			} else {
				path = "/nonexistent/path/checks.yaml"
			}

			cfg, err := LoadCustomChecks(path)
			if tt.wantErr {
				if err == nil {
					t.Fatal("expected error, got nil")
				}
				if tt.errMsg != "" {
					if got := err.Error(); !contains(got, tt.errMsg) {
						t.Errorf("error %q should contain %q", got, tt.errMsg)
					}
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if len(cfg.Checks) != tt.nChecks {
				t.Errorf("got %d checks, want %d", len(cfg.Checks), tt.nChecks)
			}
		})
	}
}

func contains(s, substr string) bool {
	return len(s) >= len(substr) && (s == substr || len(s) > 0 && containsStr(s, substr))
}
func containsStr(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------------------
// kindToNodeType
// ---------------------------------------------------------------------------

func TestKindToNodeType(t *testing.T) {
	tests := []struct {
		kind string
		want graph.NodeType
	}{
		{"workload", graph.NodeWorkload},
		{"Workload", graph.NodeWorkload},
		{"pod", graph.NodeWorkload},
		{"deployment", graph.NodeWorkload},
		{"statefulset", graph.NodeWorkload},
		{"daemonset", graph.NodeWorkload},
		{"job", graph.NodeWorkload},
		{"cronjob", graph.NodeWorkload},
		{"serviceaccount", graph.NodeServiceAccount},
		{"ServiceAccount", graph.NodeServiceAccount},
		{"sa", graph.NodeServiceAccount},
		{"role", graph.NodeRole},
		{"clusterrole", graph.NodeRole},
		{"cloudrole", graph.NodeCloudRole},
		{"scc", graph.NodeSCC},
		{"networkpolicy", graph.NodeNetworkPolicy},
		{"service", graph.NodeService},
		{"unknown", graph.NodeWorkload}, // default
	}

	for _, tt := range tests {
		t.Run(tt.kind, func(t *testing.T) {
			got := kindToNodeType(tt.kind)
			if got != tt.want {
				t.Errorf("kindToNodeType(%q) = %q, want %q", tt.kind, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// matchesNamespace
// ---------------------------------------------------------------------------

func TestMatchesNamespace(t *testing.T) {
	node := &graph.Node{Namespace: "kube-system"}

	tests := []struct {
		name  string
		match MatchCriteria
		want  bool
	}{
		{"no filter", MatchCriteria{}, true},
		{"exact match", MatchCriteria{Namespace: "kube-system"}, true},
		{"exact mismatch", MatchCriteria{Namespace: "default"}, false},
		{"pattern match", MatchCriteria{NamespacePattern: "^kube-"}, true},
		{"pattern mismatch", MatchCriteria{NamespacePattern: "^default"}, false},
		{"invalid regex", MatchCriteria{NamespacePattern: "[invalid"}, false},
		{"both match", MatchCriteria{Namespace: "kube-system", NamespacePattern: "^kube-"}, true},
		{"ns match pattern mismatch", MatchCriteria{Namespace: "kube-system", NamespacePattern: "^default"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesNamespace(node, tt.match)
			if got != tt.want {
				t.Errorf("matchesNamespace = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// matchesName
// ---------------------------------------------------------------------------

func TestMatchesName(t *testing.T) {
	node := &graph.Node{Name: "web-deploy-abc123"}

	tests := []struct {
		name  string
		match MatchCriteria
		want  bool
	}{
		{"no pattern", MatchCriteria{}, true},
		{"matching pattern", MatchCriteria{NamePattern: "^web-"}, true},
		{"non-matching", MatchCriteria{NamePattern: "^api-"}, false},
		{"invalid regex", MatchCriteria{NamePattern: "[bad"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesName(node, tt.match)
			if got != tt.want {
				t.Errorf("matchesName = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// matchesLabels
// ---------------------------------------------------------------------------

func TestMatchesLabels(t *testing.T) {
	node := &graph.Node{Labels: map[string]string{"app": "web", "env": "prod"}}

	tests := []struct {
		name   string
		labels map[string]string
		want   bool
	}{
		{"nil labels", nil, true},
		{"empty labels", map[string]string{}, true},
		{"matching single", map[string]string{"app": "web"}, true},
		{"matching both", map[string]string{"app": "web", "env": "prod"}, true},
		{"value mismatch", map[string]string{"app": "api"}, false},
		{"missing key", map[string]string{"tier": "frontend"}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := matchesLabels(node, tt.labels)
			if got != tt.want {
				t.Errorf("matchesLabels = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// evaluateCondition
// ---------------------------------------------------------------------------

func TestEvaluateCondition(t *testing.T) {
	g := buildTestGraph()

	// Retrieve nodes from the graph for tests.
	sa := g.FindNode(graph.NodeServiceAccount, "default", "my-sa")
	saSys := g.FindNode(graph.NodeServiceAccount, "kube-system", "system-sa")
	wl := g.FindNode(graph.NodeWorkload, "default", "web-deploy")
	wlSafe := g.FindNode(graph.NodeWorkload, "default", "safe-deploy")
	role := g.FindNode(graph.NodeRole, "", "cluster-admin")
	nsRole := g.FindNode(graph.NodeRole, "default", "my-role")

	tests := []struct {
		name string
		node *graph.Node
		cond CheckCondition
		want bool
	}{
		// HasLabel
		{
			name: "HasLabel present",
			node: sa,
			cond: CheckCondition{HasLabel: "app"},
			want: true,
		},
		{
			name: "HasLabel absent",
			node: sa,
			cond: CheckCondition{HasLabel: "nonexistent"},
			want: false,
		},

		// MissingLabel
		{
			name: "MissingLabel missing",
			node: saSys,
			cond: CheckCondition{MissingLabel: "app"},
			want: true,
		},
		{
			name: "MissingLabel present",
			node: sa,
			cond: CheckCondition{MissingLabel: "app"},
			want: false,
		},

		// LabelEquals
		{
			name: "LabelEquals match",
			node: sa,
			cond: CheckCondition{LabelEquals: map[string]string{"app": "web", "env": "prod"}},
			want: true,
		},
		{
			name: "LabelEquals mismatch",
			node: sa,
			cond: CheckCondition{LabelEquals: map[string]string{"app": "api"}},
			want: false,
		},

		// LabelNotEquals
		{
			name: "LabelNotEquals true",
			node: sa,
			cond: CheckCondition{LabelNotEquals: map[string]string{"app": "api"}},
			want: true,
		},
		{
			name: "LabelNotEquals false",
			node: sa,
			cond: CheckCondition{LabelNotEquals: map[string]string{"app": "web"}},
			want: false,
		},

		// HasCloudIdentity
		{
			name: "HasCloudIdentity true",
			node: sa,
			cond: CheckCondition{HasCloudIdentity: boolPtr(true)},
			want: true,
		},
		{
			name: "HasCloudIdentity false (wants true)",
			node: saSys,
			cond: CheckCondition{HasCloudIdentity: boolPtr(true)},
			want: false,
		},
		{
			name: "HasCloudIdentity false (wants false)",
			node: saSys,
			cond: CheckCondition{HasCloudIdentity: boolPtr(false)},
			want: true,
		},

		// HasSecurityContext - privileged
		{
			name: "SecurityContext privileged true",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{Privileged: boolPtr(true)}},
			want: true,
		},
		{
			name: "SecurityContext privileged false (no psc)",
			node: wlSafe,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{Privileged: boolPtr(true)}},
			want: false,
		},

		// HasSecurityContext - hostNetwork
		{
			name: "SecurityContext hostNetwork true",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{HostNetwork: boolPtr(true)}},
			want: true,
		},
		{
			name: "SecurityContext hostNetwork false mismatch",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{HostNetwork: boolPtr(false)}},
			want: false,
		},

		// HasSecurityContext - hostPID
		{
			name: "SecurityContext hostPID false match",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{HostPID: boolPtr(false)}},
			want: true,
		},

		// HasSecurityContext - runAsRoot
		{
			name: "SecurityContext runAsRoot true",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{RunAsRoot: boolPtr(true)}},
			want: true,
		},

		// HasSecurityContext - allowPrivilegeEscalation
		{
			name: "SecurityContext allowPrivilegeEscalation true",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{AllowPrivilegeEscalation: boolPtr(true)}},
			want: true,
		},

		// HasSecurityContext - capabilities
		{
			name: "SecurityContext hasCapability match",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{HasCapability: []string{"NET_ADMIN"}}},
			want: true,
		},
		{
			name: "SecurityContext hasCapability missing",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{HasCapability: []string{"NET_RAW"}}},
			want: false,
		},

		// HasSecurityContext - hasHostPath
		{
			name: "SecurityContext hasHostPath true",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{HasHostPath: boolPtr(true)}},
			want: true,
		},
		{
			name: "SecurityContext hasHostPath false (has paths)",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{HasHostPath: boolPtr(false)}},
			want: false,
		},

		// HasSecurityContext - only pod-level fields, no container fields
		{
			name: "SecurityContext pod-level only (hostIPC false)",
			node: wl,
			cond: CheckCondition{HasSecurityContext: &SecurityContext{HostIPC: boolPtr(false)}},
			want: true,
		},

		// HasRBACBinding
		{
			name: "HasRBACBinding true (has edge)",
			node: sa,
			cond: CheckCondition{HasRBACBinding: boolPtr(true)},
			want: true,
		},
		{
			name: "HasRBACBinding false (has edge)",
			node: sa,
			cond: CheckCondition{HasRBACBinding: boolPtr(false)},
			want: false,
		},
		{
			name: "HasRBACBinding true (no edge)",
			node: saSys,
			cond: CheckCondition{HasRBACBinding: boolPtr(true)},
			want: false,
		},

		// BindsToRole
		{
			name: "BindsToRole matching",
			node: sa,
			cond: CheckCondition{BindsToRole: "cluster-admin"},
			want: true,
		},
		{
			name: "BindsToRole not matching",
			node: sa,
			cond: CheckCondition{BindsToRole: "other-role"},
			want: false,
		},
		{
			name: "BindsToRole no edges",
			node: saSys,
			cond: CheckCondition{BindsToRole: "cluster-admin"},
			want: false,
		},

		// IsClusterRole
		{
			name: "IsClusterRole true",
			node: role,
			cond: CheckCondition{IsClusterRole: boolPtr(true)},
			want: true,
		},
		{
			name: "IsClusterRole false",
			node: nsRole,
			cond: CheckCondition{IsClusterRole: boolPtr(true)},
			want: false,
		},

		// And composite
		{
			name: "And both true",
			node: sa,
			cond: CheckCondition{And: []CheckCondition{
				{HasLabel: "app"},
				{HasCloudIdentity: boolPtr(true)},
			}},
			want: true,
		},
		{
			name: "And one false",
			node: sa,
			cond: CheckCondition{And: []CheckCondition{
				{HasLabel: "app"},
				{HasCloudIdentity: boolPtr(false)},
			}},
			want: false,
		},

		// Or composite
		{
			name: "Or one true",
			node: saSys,
			cond: CheckCondition{Or: []CheckCondition{
				{HasLabel: "app"},
				{HasLabel: "component"},
			}},
			want: true,
		},
		{
			name: "Or none true",
			node: saSys,
			cond: CheckCondition{Or: []CheckCondition{
				{HasLabel: "app"},
				{HasLabel: "env"},
			}},
			want: false,
		},

		// Not composite
		{
			name: "Not inverts true to false",
			node: sa,
			cond: CheckCondition{Not: &CheckCondition{HasLabel: "app"}},
			want: false,
		},
		{
			name: "Not inverts false to true",
			node: sa,
			cond: CheckCondition{Not: &CheckCondition{HasLabel: "missing"}},
			want: true,
		},

		// Default (no condition fields set)
		{
			name: "empty condition returns false",
			node: sa,
			cond: CheckCondition{},
			want: false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := evaluateCondition(g, tt.node, tt.cond)
			if got != tt.want {
				t.Errorf("evaluateCondition = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// checkSecurityContext
// ---------------------------------------------------------------------------

func TestCheckSecurityContext(t *testing.T) {
	nodeWithPSC := &graph.Node{
		Metadata: graph.NodeMetadata{
			PodSecurityContext: &graph.PodSecurityContext{
				HostNetwork: true,
				Containers: []graph.ContainerSecurityInfo{
					{
						Name:                     "c1",
						Privileged:               false,
						RunAsRoot:                false,
						AllowPrivilegeEscalation: false,
						Capabilities:             []string{"NET_ADMIN"},
					},
				},
			},
		},
	}

	nodeNoPSC := &graph.Node{}

	tests := []struct {
		name string
		node *graph.Node
		sc   *SecurityContext
		want bool
	}{
		{"nil psc", nodeNoPSC, &SecurityContext{}, false},
		{"hostNetwork match", nodeWithPSC, &SecurityContext{HostNetwork: boolPtr(true)}, true},
		{"hostNetwork mismatch", nodeWithPSC, &SecurityContext{HostNetwork: boolPtr(false)}, false},
		{"privileged false match", nodeWithPSC, &SecurityContext{Privileged: boolPtr(false)}, true},
		{"privileged true no match", nodeWithPSC, &SecurityContext{Privileged: boolPtr(true)}, false},
		{"capability found", nodeWithPSC, &SecurityContext{HasCapability: []string{"NET_ADMIN"}}, true},
		{"capability not found", nodeWithPSC, &SecurityContext{HasCapability: []string{"SYS_ADMIN"}}, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkSecurityContext(tt.node, tt.sc)
			if got != tt.want {
				t.Errorf("checkSecurityContext = %v, want %v", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// checkMissingSecurityField
// ---------------------------------------------------------------------------

func TestCheckMissingSecurityField(t *testing.T) {
	nodeNoPSC := &graph.Node{}

	nodeWithCtx := &graph.Node{
		Metadata: graph.NodeMetadata{
			PodSecurityContext: &graph.PodSecurityContext{
				Containers: []graph.ContainerSecurityInfo{
					{
						HasSecurityContext:     true,
						RunAsRoot:              false,
						ReadOnlyRootFilesystem: true,
						Capabilities:           []string{"NET_ADMIN"},
					},
				},
			},
		},
	}

	nodeNoCtx := &graph.Node{
		Metadata: graph.NodeMetadata{
			PodSecurityContext: &graph.PodSecurityContext{
				Containers: []graph.ContainerSecurityInfo{
					{
						HasSecurityContext:     false,
						RunAsRoot:              true,
						ReadOnlyRootFilesystem: false,
						Capabilities:           nil,
					},
				},
			},
		},
	}

	tests := []struct {
		name  string
		node  *graph.Node
		field string
		want  bool
	}{
		{"nil psc", nodeNoPSC, "securitycontext", true},
		{"securitycontext present", nodeWithCtx, "securitycontext", false},
		{"securitycontext absent", nodeNoCtx, "securitycontext", true},
		{"readonlyrootfilesystem present", nodeWithCtx, "readonlyrootfilesystem", false},
		{"readonlyrootfilesystem absent", nodeNoCtx, "readonlyrootfilesystem", true},
		{"capabilities present", nodeWithCtx, "capabilities", false},
		{"capabilities absent", nodeNoCtx, "capabilities", true},
		// runasnonroot: returns false when !RunAsRoot && HasSecurityContext
		{"runasnonroot configured", nodeWithCtx, "runasnonroot", false},
		// nodeNoCtx has RunAsRoot=true, HasSecurityContext=false => never hits the false return
		{"runasnonroot not configured", nodeNoCtx, "runasnonroot", true},
		{"unknown field", nodeWithCtx, "unknownfield", false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := checkMissingSecurityField(tt.node, tt.field)
			if got != tt.want {
				t.Errorf("checkMissingSecurityField(%q) = %v, want %v", tt.field, got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// createFinding
// ---------------------------------------------------------------------------

func TestCreateFinding(t *testing.T) {
	check := CustomCheck{
		ID:          "TST001",
		Name:        "Test",
		Category:    "security",
		Severity:    "high",
		Description: "desc",
		Remediation: "fix it",
		Metadata:    map[string]string{"key": "val"},
	}
	node := &graph.Node{
		Type:      graph.NodeServiceAccount,
		Namespace: "default",
		Name:      "my-sa",
	}

	f := createFinding(check, node, "details here")

	if f.CheckID != "TST001" {
		t.Errorf("CheckID = %q", f.CheckID)
	}
	if f.Severity != "high" {
		t.Errorf("Severity = %q", f.Severity)
	}
	if len(f.Affected) != 1 {
		t.Fatalf("Affected len = %d", len(f.Affected))
	}
	a := f.Affected[0]
	if a.Kind != string(graph.NodeServiceAccount) {
		t.Errorf("Kind = %q", a.Kind)
	}
	if a.Namespace != "default" || a.Name != "my-sa" {
		t.Errorf("Namespace/Name = %q/%q", a.Namespace, a.Name)
	}
	if a.Details != "details here" {
		t.Errorf("Details = %q", a.Details)
	}
	if f.Metadata["key"] != "val" {
		t.Errorf("Metadata = %v", f.Metadata)
	}
}

// ---------------------------------------------------------------------------
// getConditionDetails
// ---------------------------------------------------------------------------

func TestGetConditionDetails(t *testing.T) {
	tests := []struct {
		name string
		cond CheckCondition
		want string
	}{
		{"missing label", CheckCondition{MissingLabel: "app"}, "Missing label: app"},
		{"has security context", CheckCondition{HasSecurityContext: &SecurityContext{}}, "Security context matches condition"},
		{"missing security field", CheckCondition{MissingSecurityField: "runAsNonRoot"}, "Missing security field: runAsNonRoot"},
		{"has cloud identity true", CheckCondition{HasCloudIdentity: boolPtr(true)}, "Has cloud identity binding"},
		{"has cloud identity false", CheckCondition{HasCloudIdentity: boolPtr(false)}, "Missing cloud identity binding"},
		{"binds to role", CheckCondition{BindsToRole: "admin"}, "Binds to role: admin"},
		{"default", CheckCondition{HasLabel: "x"}, "Condition matched"},
		{"empty", CheckCondition{}, "Condition matched"},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := getConditionDetails(tt.cond)
			if got != tt.want {
				t.Errorf("getConditionDetails = %q, want %q", got, tt.want)
			}
		})
	}
}

// ---------------------------------------------------------------------------
// RunCustomChecks - integration-style tests
// ---------------------------------------------------------------------------

func TestRunCustomChecks(t *testing.T) {
	g := buildTestGraph()

	t.Run("Exists condition", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "E001", Name: "SA exists", Category: "audit", Severity: "info",
			Description: "Find SAs",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{Exists: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 2 { // my-sa + system-sa
			t.Errorf("got %d findings, want 2", len(findings))
		}
	})

	t.Run("Exists with namespace filter", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "E002", Name: "SA in default", Category: "audit", Severity: "info",
			Description: "Find SAs in default",
			Match:       MatchCriteria{Kind: "ServiceAccount", Namespace: "default"},
			Condition:   CheckCondition{Exists: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("Exists with namespace pattern", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "E003", Name: "SA in kube-*", Category: "audit", Severity: "info",
			Description: "Find SAs in kube namespaces",
			Match:       MatchCriteria{Kind: "ServiceAccount", NamespacePattern: "^kube-"},
			Condition:   CheckCondition{Exists: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("Exists with name pattern", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "E004", Name: "web workloads", Category: "audit", Severity: "info",
			Description: "Find web workloads",
			Match:       MatchCriteria{Kind: "Workload", NamePattern: "^web-"},
			Condition:   CheckCondition{Exists: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("Exists with label filter", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "E005", Name: "app=web SAs", Category: "audit", Severity: "info",
			Description: "Find app=web SAs",
			Match:       MatchCriteria{Kind: "ServiceAccount", Labels: map[string]string{"app": "web"}},
			Condition:   CheckCondition{Exists: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("NotExists - no matches triggers finding", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "N001", Name: "missing SCC", Category: "audit", Severity: "warning",
			Description: "No SCC found",
			Match:       MatchCriteria{Kind: "scc"},
			Condition:   CheckCondition{NotExists: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
		if len(findings) == 1 && findings[0].Affected[0].Details != "No matching resources found" {
			t.Errorf("unexpected details: %q", findings[0].Affected[0].Details)
		}
	})

	t.Run("NotExists - matches exist so no finding", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "N002", Name: "missing SA", Category: "audit", Severity: "warning",
			Description: "No SA found",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{NotExists: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 0 {
			t.Errorf("got %d findings, want 0", len(findings))
		}
	})

	t.Run("HasLabel condition", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "L001", Name: "SA with app label", Category: "audit", Severity: "info",
			Description: "SA has app label",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{HasLabel: "app"},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("MissingLabel condition", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "L002", Name: "SA missing app label", Category: "audit", Severity: "info",
			Description: "SA missing app",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{MissingLabel: "app"},
		}}}
		findings := RunCustomChecks(g, cfg)
		// system-sa has no "app" label
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("HasSecurityContext privileged", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "S001", Name: "Privileged workload", Category: "security", Severity: "critical",
			Description: "Privileged container",
			Match:       MatchCriteria{Kind: "Workload"},
			Condition:   CheckCondition{HasSecurityContext: &SecurityContext{Privileged: boolPtr(true)}},
		}}}
		findings := RunCustomChecks(g, cfg)
		// web-deploy is privileged, safe-deploy has no PSC
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("MissingSecurityField", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "S002", Name: "Missing security context", Category: "security", Severity: "high",
			Description: "No security context",
			Match:       MatchCriteria{Kind: "Workload"},
			Condition:   CheckCondition{MissingSecurityField: "securitycontext"},
		}}}
		findings := RunCustomChecks(g, cfg)
		// safe-deploy has nil PSC (returns true), web-deploy has HasSecurityContext=true (returns false)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("HasCloudIdentity", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "C001", Name: "SA with cloud identity", Category: "cloud", Severity: "info",
			Description: "Cloud bound SA",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{HasCloudIdentity: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("HasRBACBinding", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "R001", Name: "SA with RBAC", Category: "rbac", Severity: "info",
			Description: "Has RBAC binding",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{HasRBACBinding: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("IsClusterRole", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "R002", Name: "Cluster roles", Category: "rbac", Severity: "info",
			Description: "Is cluster role",
			Match:       MatchCriteria{Kind: "Role"},
			Condition:   CheckCondition{IsClusterRole: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("And composite condition", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "A001", Name: "SA with app label and cloud", Category: "audit", Severity: "info",
			Description: "Both conditions",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition: CheckCondition{And: []CheckCondition{
				{HasLabel: "app"},
				{HasCloudIdentity: boolPtr(true)},
			}},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("Or composite condition", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "O001", Name: "SA with app or component label", Category: "audit", Severity: "info",
			Description: "Either label",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition: CheckCondition{Or: []CheckCondition{
				{HasLabel: "app"},
				{HasLabel: "component"},
			}},
		}}}
		findings := RunCustomChecks(g, cfg)
		// my-sa has "app", system-sa has "component"
		if len(findings) != 2 {
			t.Errorf("got %d findings, want 2", len(findings))
		}
	})

	t.Run("Not composite condition", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "NOT1", Name: "SA without cloud identity", Category: "audit", Severity: "info",
			Description: "No cloud",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{Not: &CheckCondition{HasCloudIdentity: boolPtr(true)}},
		}}}
		findings := RunCustomChecks(g, cfg)
		// system-sa has no cloud identity
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("CountGreaterThan triggers", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "CT01", Name: "Too many SAs", Category: "audit", Severity: "warning",
			Description: "Many SAs",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{CountGreaterThan: intPtr(1)},
		}}}
		findings := RunCustomChecks(g, cfg)
		// 2 SAs > 1
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
		if len(findings) == 1 {
			if !containsStr(findings[0].Affected[0].Details, "exceeds threshold") {
				t.Errorf("details = %q", findings[0].Affected[0].Details)
			}
		}
	})

	t.Run("CountGreaterThan does not trigger", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "CT02", Name: "Not too many SAs", Category: "audit", Severity: "warning",
			Description: "Few SAs",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{CountGreaterThan: intPtr(5)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 0 {
			t.Errorf("got %d findings, want 0", len(findings))
		}
	})

	t.Run("CountLessThan triggers", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "CT03", Name: "Too few cloud roles", Category: "audit", Severity: "warning",
			Description: "Few cloud roles",
			Match:       MatchCriteria{Kind: "cloudrole"},
			Condition:   CheckCondition{CountLessThan: intPtr(3)},
		}}}
		findings := RunCustomChecks(g, cfg)
		// 1 cloud role < 3
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
		if len(findings) == 1 {
			if !containsStr(findings[0].Affected[0].Details, "below threshold") {
				t.Errorf("details = %q", findings[0].Affected[0].Details)
			}
		}
	})

	t.Run("CountLessThan does not trigger", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "CT04", Name: "Enough SAs", Category: "audit", Severity: "warning",
			Description: "Enough SAs",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{CountLessThan: intPtr(1)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 0 {
			t.Errorf("got %d findings, want 0", len(findings))
		}
	})

	t.Run("Multiple checks in one config", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{
			{
				ID: "M001", Name: "Check 1", Category: "a", Severity: "info",
				Description: "first",
				Match:       MatchCriteria{Kind: "ServiceAccount"},
				Condition:   CheckCondition{HasLabel: "app"},
			},
			{
				ID: "M002", Name: "Check 2", Category: "b", Severity: "info",
				Description: "second",
				Match:       MatchCriteria{Kind: "Role"},
				Condition:   CheckCondition{IsClusterRole: boolPtr(true)},
			},
		}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 2 {
			t.Errorf("got %d findings, want 2", len(findings))
		}
	})

	t.Run("No findings when nothing matches", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "Z001", Name: "Nonexistent", Category: "audit", Severity: "info",
			Description: "nope",
			Match:       MatchCriteria{Kind: "ServiceAccount", Namespace: "nonexistent"},
			Condition:   CheckCondition{Exists: boolPtr(true)},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 0 {
			t.Errorf("got %d findings, want 0", len(findings))
		}
	})

	t.Run("LabelEquals condition via RunCustomChecks", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "LE01", Name: "Label equals", Category: "audit", Severity: "info",
			Description: "label eq",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{LabelEquals: map[string]string{"env": "prod"}},
		}}}
		findings := RunCustomChecks(g, cfg)
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})

	t.Run("LabelNotEquals condition via RunCustomChecks", func(t *testing.T) {
		cfg := &CustomCheckConfig{Checks: []CustomCheck{{
			ID: "LN01", Name: "Label not equals", Category: "audit", Severity: "info",
			Description: "label neq",
			Match:       MatchCriteria{Kind: "ServiceAccount"},
			Condition:   CheckCondition{LabelNotEquals: map[string]string{"env": "prod"}},
		}}}
		findings := RunCustomChecks(g, cfg)
		// system-sa does not have env=prod
		if len(findings) != 1 {
			t.Errorf("got %d findings, want 1", len(findings))
		}
	})
}
