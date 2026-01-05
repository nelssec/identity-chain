package remediation

import (
	"fmt"

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
			combined += fmt.Sprintf("# %s: %s\n", r.CheckID, m.Description)
			combined += m.YAML + "\n"
		}
	}

	rr.CombinedManifests = combined
	return combined
}

func toYAMLString(obj interface{}) string {
	data, err := yaml.Marshal(obj)
	if err != nil {
		return ""
	}
	return string(data)
}
