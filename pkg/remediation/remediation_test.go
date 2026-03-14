package remediation

import (
	"strings"
	"testing"
)

func TestRemediation_ToYAML_SingleManifest(t *testing.T) {
	r := Remediation{
		Manifests: []Manifest{
			{Action: "create", Description: "Create role", YAML: "apiVersion: v1\nkind: Role"},
		},
	}

	got, err := r.ToYAML()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "apiVersion: v1") {
		t.Errorf("expected YAML to contain apiVersion, got: %s", got)
	}
	if strings.Contains(got, "---") {
		t.Errorf("single manifest should not contain separator")
	}
}

func TestRemediation_ToYAML_MultipleManifests(t *testing.T) {
	r := Remediation{
		Manifests: []Manifest{
			{Action: "create", Description: "First", YAML: "kind: Role"},
			{Action: "create", Description: "Second", YAML: "kind: ClusterRole"},
		},
	}

	got, err := r.ToYAML()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if !strings.Contains(got, "---\n") {
		t.Errorf("multiple manifests should contain separator")
	}
	if !strings.Contains(got, "kind: Role") {
		t.Errorf("should contain first manifest")
	}
	if !strings.Contains(got, "kind: ClusterRole") {
		t.Errorf("should contain second manifest")
	}
}

func TestRemediation_ToYAML_Empty(t *testing.T) {
	r := Remediation{}
	got, err := r.ToYAML()
	if err != nil {
		t.Fatalf("unexpected error: %v", err)
	}
	if got != "" {
		t.Errorf("expected empty string for no manifests, got: %q", got)
	}
}

func TestRemediationResult_GenerateCombinedManifests(t *testing.T) {
	rr := &RemediationResult{
		Remediations: []Remediation{
			{
				CheckID:   "RBAC001",
				FindingID: "RBAC001-cluster-wide-admin-binding",
				Severity:  "critical",
				Manifests: []Manifest{
					{Action: "create", Description: "Create role", YAML: "kind: Role\nname: test"},
				},
			},
			{
				CheckID:   "PSS001",
				FindingID: "PSS001-privileged-container",
				Severity:  "high",
				Manifests: []Manifest{
					{Action: "patch", Description: "Patch deployment", YAML: "kind: Deployment\nname: app"},
				},
			},
		},
	}

	combined := rr.GenerateCombinedManifests()

	if combined == "" {
		t.Fatal("combined manifests should not be empty")
	}
	if !strings.Contains(combined, "# idc: RBAC001-cluster-wide-admin-binding critical") {
		t.Error("should contain idc traceability comment for RBAC finding")
	}
	if !strings.Contains(combined, "# Action: Create role") {
		t.Error("should contain action comment for RBAC finding")
	}
	if !strings.Contains(combined, "# idc: PSS001-privileged-container high") {
		t.Error("should contain idc traceability comment for PSS finding")
	}
	if !strings.Contains(combined, "# Action: Patch deployment") {
		t.Error("should contain action comment for PSS finding")
	}
	if !strings.Contains(combined, "---\n") {
		t.Error("should contain separator between manifests")
	}
	if rr.CombinedManifests != combined {
		t.Error("CombinedManifests field should be set")
	}
}

func TestRemediationResult_GenerateCombinedManifests_Dedup(t *testing.T) {
	yaml := "kind: Role\nname: shared"
	rr := &RemediationResult{
		Remediations: []Remediation{
			{
				CheckID: "RBAC001",
				Manifests: []Manifest{
					{Action: "create", Description: "Create role", YAML: yaml},
				},
			},
			{
				CheckID: "RBAC002",
				Manifests: []Manifest{
					{Action: "create", Description: "Create role", YAML: yaml},
				},
			},
		},
	}

	combined := rr.GenerateCombinedManifests()
	count := strings.Count(combined, yaml)
	if count != 1 {
		t.Errorf("duplicate YAML should be deduplicated, found %d occurrences", count)
	}
}

func TestRemediationResult_GenerateCombinedManifests_Empty(t *testing.T) {
	rr := &RemediationResult{}
	combined := rr.GenerateCombinedManifests()
	if combined != "" {
		t.Errorf("expected empty combined manifests, got: %q", combined)
	}
}

func TestToYAMLString(t *testing.T) {
	tests := []struct {
		name  string
		input interface{}
		want  string
	}{
		{
			name:  "simple map",
			input: map[string]string{"key": "value"},
			want:  "key: value",
		},
		{
			name:  "struct",
			input: ResourceRef{Kind: "Pod", Name: "test", Namespace: "default"},
			want:  "kind: Pod",
		},
		{
			name:  "nil",
			input: nil,
			want:  "null",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := toYAMLString(tt.input)
			if !strings.Contains(got, tt.want) {
				t.Errorf("toYAMLString() = %q, want to contain %q", got, tt.want)
			}
		})
	}
}
