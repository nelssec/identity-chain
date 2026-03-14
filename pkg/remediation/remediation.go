package remediation

import (
	"fmt"
	"strings"

	"gopkg.in/yaml.v3"
)

type RemediationType string

const (
	RemediationRBAC          RemediationType = "rbac"
	RemediationPodSecurity   RemediationType = "pod_security"
	RemediationNetworkPolicy RemediationType = "network_policy"
	RemediationServiceAccount RemediationType = "service_account"
)

type Remediation struct {
	Type        RemediationType `json:"type" yaml:"type"`
	FindingID   string          `json:"finding_id" yaml:"finding_id"`
	CheckID     string          `json:"check_id" yaml:"check_id"`
	Severity    string          `json:"severity" yaml:"severity"`
	Description string          `json:"description" yaml:"description"`
	Resource    ResourceRef     `json:"resource" yaml:"resource"`
	Action      string          `json:"action" yaml:"action"`
	Manifests   []Manifest      `json:"manifests" yaml:"manifests"`
}

type ResourceRef struct {
	Kind      string `json:"kind" yaml:"kind"`
	Name      string `json:"name" yaml:"name"`
	Namespace string `json:"namespace,omitempty" yaml:"namespace,omitempty"`
}

type Manifest struct {
	Action      string `json:"action" yaml:"action"`
	Description string `json:"description" yaml:"description"`
	YAML        string `json:"yaml" yaml:"yaml"`
}

type RemediationResult struct {
	TotalFindings     int           `json:"total_findings" yaml:"total_findings"`
	RemediableCount   int           `json:"remediable_count" yaml:"remediable_count"`
	NonRemediable     int           `json:"non_remediable" yaml:"non_remediable"`
	Remediations      []Remediation `json:"remediations" yaml:"remediations"`
	CombinedManifests string        `json:"combined_manifests,omitempty" yaml:"combined_manifests,omitempty"`
}

func (r *Remediation) ToYAML() (string, error) {
	var combined string
	for i, m := range r.Manifests {
		if i > 0 {
			combined += "---\n"
		}
		combined += m.YAML + "\n"
	}
	return combined, nil
}

func (rr *RemediationResult) GenerateCombinedManifests() string {
	var combined string
	seen := make(map[string]bool)

	for _, r := range rr.Remediations {
		for _, m := range r.Manifests {
			key := fmt.Sprintf("%s-%s", m.Action, m.YAML)
			if seen[key] {
				continue
			}
			seen[key] = true

			if combined != "" {
				combined += "---\n"
			}
			combined += fmt.Sprintf("# idc: %s %s\n", r.FindingID, r.Severity)
			combined += fmt.Sprintf("# action: %s | %s\n", m.Action, m.Description)
			combined += m.YAML + "\n"
		}
	}

	rr.CombinedManifests = combined
	return combined
}

// GenerateDryRunYAML generates clean YAML output suitable for kubectl apply.
// It skips review-only manifests (where YAML starts with #) and includes
// idc traceability comments before each manifest.
func (rr *RemediationResult) GenerateDryRunYAML() string {
	var parts []string
	seen := make(map[string]bool)

	for _, r := range rr.Remediations {
		for _, m := range r.Manifests {
			trimmed := strings.TrimSpace(m.YAML)
			if trimmed == "" || strings.HasPrefix(trimmed, "#") {
				continue
			}

			key := fmt.Sprintf("%s-%s", m.Action, m.YAML)
			if seen[key] {
				continue
			}
			seen[key] = true

			block := fmt.Sprintf("# idc: %s %s\n%s", r.FindingID, r.Severity, m.YAML)
			parts = append(parts, block)
		}
	}

	if len(parts) == 0 {
		return ""
	}
	return strings.Join(parts, "\n---\n") + "\n"
}

func toYAMLString(obj interface{}) string {
	data, err := yaml.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(data)
}
