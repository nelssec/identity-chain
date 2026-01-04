package output

import (
	"encoding/json"
	"fmt"
	"html"
	"io"
	"strings"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type HTMLWriter struct {
	w io.Writer
}

func NewHTMLWriter(w io.Writer) *HTMLWriter {
	return &HTMLWriter{w: w}
}

type htmlNode struct {
	ID               string        `json:"id"`
	Name             string        `json:"name"`
	Type             string        `json:"type"`
	Namespace        string        `json:"namespace,omitempty"`
	Risk             string        `json:"risk"`
	RiskScore        int           `json:"riskScore"`
	Layer            int           `json:"layer"`
	Kind             string        `json:"kind,omitempty"`
	CloudARN         string        `json:"cloudArn,omitempty"`
	Verbs            []string      `json:"verbs,omitempty"`
	InUse            bool          `json:"inUse"`
	IsOverprivileged bool          `json:"isOverprivileged"`
	TotalPerms       int           `json:"totalPerms"`
	RiskFactors      []riskFactor  `json:"riskFactors,omitempty"`
	Permissions      []permission  `json:"permissions,omitempty"`
	UsedBy           []string      `json:"usedBy,omitempty"`
	CloudPolicies    []cloudPolicy `json:"cloudPolicies,omitempty"`
	BlastRadius      []string      `json:"blastRadius,omitempty"`
}

type cloudPolicy struct {
	Name     string   `json:"name"`
	Actions  []string `json:"actions"`
	IsAdmin  bool     `json:"isAdmin"`
	Severity string   `json:"severity"`
}

type riskFactor struct {
	Category    string `json:"category"`
	Description string `json:"description"`
	Severity    string `json:"severity"`
}

type permission struct {
	Resource string   `json:"resource"`
	Verbs    []string `json:"verbs"`
	ViaRole  string   `json:"viaRole"`
	Severity string   `json:"severity"`
}

type htmlLink struct {
	Source string   `json:"source"`
	Target string   `json:"target"`
	Type   string   `json:"type"`
	Risk   string   `json:"risk"`
	Label  string   `json:"label,omitempty"`
	Verbs  []string `json:"verbs,omitempty"`
	Value  int      `json:"value"`
}

type htmlGraph struct {
	Nodes []htmlNode `json:"nodes"`
	Links []htmlLink `json:"links"`
	Meta  htmlMeta   `json:"meta"`
}

type htmlMeta struct {
	Title            string `json:"title"`
	GeneratedAt      string `json:"generatedAt"`
	TotalNodes       int    `json:"totalNodes"`
	TotalLinks       int    `json:"totalLinks"`
	CriticalCount    int    `json:"criticalCount"`
	HighCount        int    `json:"highCount"`
	CloudRoles       int    `json:"cloudRoles"`
	OverprivilegedSA int    `json:"overprivilegedSA"`
	TotalSA          int    `json:"totalSA"`
	UnusedSA         int    `json:"unusedSA"`
}

func (h *HTMLWriter) WriteBlastResult(result *analysis.BlastResult) error {
	if result == nil {
		return fmt.Errorf("no result to render")
	}
	hg := h.buildBlastGraph(result)
	return h.renderHTML(hg)
}

func (h *HTMLWriter) WriteBlastResults(results []*analysis.BlastResult) error {
	hg := h.buildMultiBlastGraph(results)
	return h.renderHTML(hg)
}

func (h *HTMLWriter) WriteGraph(g *graph.Graph) error {
	hg := h.buildFullGraph(g)
	return h.renderHTML(hg)
}

func (h *HTMLWriter) WriteStats(stats graph.GraphStats) error {
	return fmt.Errorf("stats not supported in HTML format, use graph or blast commands")
}

func (h *HTMLWriter) WritePrivescResults(results []*analysis.PrivescResult) error {
	return fmt.Errorf("privesc results not supported in HTML format, use table or json output")
}

func (h *HTMLWriter) WriteWhoCanResult(result *analysis.WhoCanResult) error {
	return fmt.Errorf("whocan results not supported in HTML format, use table or json output")
}

func (h *HTMLWriter) WriteWhatCanResult(result *analysis.ReverseRBACResult) error {
	return fmt.Errorf("whatcan results not supported in HTML format, use table or json output")
}

func (h *HTMLWriter) WriteRBACAuditResult(result *analysis.RBACAuditResult) error {
	return fmt.Errorf("rbac-audit results not supported in HTML format, use table or json output")
}

func (h *HTMLWriter) WriteCloudAuditResult(result *analysis.CloudIAMAuditResult) error {
	return fmt.Errorf("cloud-audit results not supported in HTML format, use table or json output")
}

func getLayer(nodeType string) int {
	switch nodeType {
	case "workload":
		return 0
	case "serviceaccount", "service_account":
		return 1
	case "role":
		return 2
	case "resource", "k8s_resource":
		return 3
	case "cloudrole", "cloud_role":
		return 4
	default:
		return 3
	}
}

func (h *HTMLWriter) buildBlastGraph(result *analysis.BlastResult) htmlGraph {
	nodes := make([]htmlNode, 0)
	links := make([]htmlLink, 0)
	criticalCount := 0
	highCount := 0
	cloudCount := 0

	if result.SourceWorkload != nil {
		nodes = append(nodes, htmlNode{
			ID:        escapeForJSON(result.SourceWorkload.ID),
			Name:      escapeForJSON(result.SourceWorkload.Name),
			Type:      "workload",
			Namespace: escapeForJSON(result.SourceWorkload.Namespace),
			Risk:      string(result.MaxSeverity),
			RiskScore: severityScore(result.MaxSeverity),
			Layer:     0,
			Kind:      escapeForJSON(result.SourceWorkload.Metadata.WorkloadKind),
			InUse:     true,
		})
	}

	if result.ServiceAccount != nil {
		saRisk := "low"
		riskFactors := make([]riskFactor, 0)
		perms := make([]permission, 0)
		blastRadius := make([]string, 0)

		if result.ServiceAccount.HasCloudIdentity() {
			saRisk = "high"
			highCount++
			riskFactors = append(riskFactors, riskFactor{
				Category:    "Cloud Identity",
				Description: "Has cloud IAM access",
				Severity:    "high",
			})
		}

		for _, res := range result.K8sResources {
			perms = append(perms, permission{
				Resource: res.Resource.Name,
				Verbs:    res.Verbs,
				ViaRole:  res.ViaRole,
				Severity: string(res.Severity),
			})

			blastDesc := describeK8sResourceAccess(res.Resource.Name, res.Resource.Namespace, res.Verbs, res.Severity)
			if blastDesc != "" {
				blastRadius = append(blastRadius, blastDesc)
			}

			if res.Severity == graph.SeverityCritical {
				riskFactors = append(riskFactors, riskFactor{
					Category:    "Critical Access",
					Description: fmt.Sprintf("Can access %s", res.Resource.Name),
					Severity:    "critical",
				})
				saRisk = "critical"
				criticalCount++
			} else if res.Severity == graph.SeverityHigh && saRisk != "critical" {
				saRisk = "high"
			}
		}

		nodes = append(nodes, htmlNode{
			ID:               escapeForJSON(result.ServiceAccount.ID),
			Name:             escapeForJSON(result.ServiceAccount.Name),
			Type:             "serviceaccount",
			Namespace:        escapeForJSON(result.ServiceAccount.Namespace),
			Risk:             saRisk,
			RiskScore:        severityScore(graph.Severity(saRisk)),
			Layer:            1,
			CloudARN:         escapeForJSON(result.ServiceAccount.Metadata.CloudRoleARN),
			InUse:            true,
			IsOverprivileged: result.MaxSeverity == graph.SeverityCritical || result.MaxSeverity == graph.SeverityHigh,
			TotalPerms:       result.TotalK8sPerms,
			RiskFactors:      riskFactors,
			Permissions:      perms,
			BlastRadius:      blastRadius,
		})

		if result.SourceWorkload != nil {
			links = append(links, htmlLink{
				Source: result.SourceWorkload.ID,
				Target: result.ServiceAccount.ID,
				Type:   "uses",
				Risk:   "info",
				Label:  "uses",
				Value:  1,
			})
		}
	}

	rolesSeen := make(map[string]bool)
	for _, access := range result.K8sResources {
		if !rolesSeen[access.ViaRole] {
			rolesSeen[access.ViaRole] = true
			roleID := "role:" + access.ViaRole
			nodes = append(nodes, htmlNode{
				ID:        escapeForJSON(roleID),
				Name:      escapeForJSON(access.ViaRole),
				Type:      "role",
				Risk:      "medium",
				RiskScore: 50,
				Layer:     2,
			})

			if result.ServiceAccount != nil {
				links = append(links, htmlLink{
					Source: result.ServiceAccount.ID,
					Target: roleID,
					Type:   "binds",
					Risk:   "info",
					Label:  "binds",
					Value:  2,
				})
			}
		}
	}

	resourcesSeen := make(map[string]bool)
	for _, access := range result.K8sResources {
		resourceID := access.Resource.ID
		if !resourcesSeen[resourceID] {
			resourcesSeen[resourceID] = true
			nodes = append(nodes, htmlNode{
				ID:        escapeForJSON(resourceID),
				Name:      escapeForJSON(access.Resource.Name),
				Type:      "resource",
				Namespace: escapeForJSON(access.Resource.Namespace),
				Risk:      string(access.Severity),
				RiskScore: severityScore(access.Severity),
				Layer:     3,
				Kind:      escapeForJSON(access.Resource.Metadata.ResourceKind),
				Verbs:     access.Verbs,
			})

			if access.Severity == graph.SeverityCritical {
				criticalCount++
			} else if access.Severity == graph.SeverityHigh {
				highCount++
			}
		}

		roleID := "role:" + access.ViaRole
		links = append(links, htmlLink{
			Source: roleID,
			Target: resourceID,
			Type:   "grants",
			Risk:   string(access.Severity),
			Label:  formatVerbs(access.Verbs),
			Verbs:  access.Verbs,
			Value:  severityScore(access.Severity) / 20,
		})
	}

	for _, access := range result.CloudRoles {
		cloudID := "cloud:" + sanitizeCloudID(access.RoleARN)

		policies := make([]cloudPolicy, 0)
		for _, p := range access.Policies {
			escapedActions := make([]string, len(p.Actions))
			for i, a := range p.Actions {
				escapedActions[i] = escapeForJSON(a)
			}
			policies = append(policies, cloudPolicy{
				Name:     escapeForJSON(p.Name),
				Actions:  escapedActions,
				IsAdmin:  p.IsAdmin,
				Severity: string(p.Severity),
			})
		}

		escapedBlastRadius := make([]string, len(access.BlastRadius))
		for i, br := range access.BlastRadius {
			escapedBlastRadius[i] = escapeForJSON(br)
		}

		nodes = append(nodes, htmlNode{
			ID:            escapeForJSON(cloudID),
			Name:          escapeForJSON(shortARN(access.RoleARN)),
			Type:          "cloudrole",
			Risk:          "high",
			RiskScore:     80,
			Layer:         4,
			CloudARN:      escapeForJSON(access.RoleARN),
			Kind:          escapeForJSON(access.Provider),
			CloudPolicies: policies,
			BlastRadius:   escapedBlastRadius,
		})
		cloudCount++

		if result.ServiceAccount != nil {
			links = append(links, htmlLink{
				Source: result.ServiceAccount.ID,
				Target: cloudID,
				Type:   "assumes",
				Risk:   "high",
				Label:  "assumes",
				Value:  4,
			})
		}
	}

	title := "Blast Radius Analysis"
	if result.SourceWorkload != nil {
		title = fmt.Sprintf("%s/%s", result.SourceWorkload.Namespace, result.SourceWorkload.Name)
	}

	return htmlGraph{
		Nodes: nodes,
		Links: links,
		Meta: htmlMeta{
			Title:         title,
			GeneratedAt:   time.Now().Format(time.RFC3339),
			TotalNodes:    len(nodes),
			TotalLinks:    len(links),
			CriticalCount: criticalCount,
			HighCount:     highCount,
			CloudRoles:    cloudCount,
		},
	}
}

func (h *HTMLWriter) buildMultiBlastGraph(results []*analysis.BlastResult) htmlGraph {
	nodes := make([]htmlNode, 0)
	links := make([]htmlLink, 0)
	nodesSeen := make(map[string]bool)
	linksSeen := make(map[string]bool)
	criticalCount := 0
	highCount := 0
	cloudCount := 0
	overprivilegedCount := 0
	totalSA := 0
	unusedSA := 0
	saInUse := make(map[string][]string)

	for _, result := range results {
		if result.SourceWorkload != nil && result.ServiceAccount != nil {
			saInUse[result.ServiceAccount.ID] = append(saInUse[result.ServiceAccount.ID], result.SourceWorkload.Name)
		}
	}

	for _, result := range results {
		if result.SourceWorkload != nil && !nodesSeen[result.SourceWorkload.ID] {
			nodesSeen[result.SourceWorkload.ID] = true
			nodes = append(nodes, htmlNode{
				ID:        result.SourceWorkload.ID,
				Name:      result.SourceWorkload.Name,
				Type:      "workload",
				Namespace: result.SourceWorkload.Namespace,
				Risk:      string(result.MaxSeverity),
				RiskScore: severityScore(result.MaxSeverity),
				Layer:     0,
				Kind:      result.SourceWorkload.Metadata.WorkloadKind,
				InUse:     true,
			})
		}

		if result.ServiceAccount != nil && !nodesSeen[result.ServiceAccount.ID] {
			nodesSeen[result.ServiceAccount.ID] = true
			totalSA++

			saRisk := string(result.MaxSeverity)
			riskFactors := make([]riskFactor, 0)
			perms := make([]permission, 0)
			isOverpriv := result.MaxSeverity == graph.SeverityCritical || result.MaxSeverity == graph.SeverityHigh

			if result.ServiceAccount.HasCloudIdentity() {
				riskFactors = append(riskFactors, riskFactor{
					Category:    "Cloud Identity",
					Description: "Has cloud IAM access - blast radius extends to cloud",
					Severity:    "high",
				})
			}

			for _, res := range result.K8sResources {
				perms = append(perms, permission{
					Resource: res.Resource.Name,
					Verbs:    res.Verbs,
					ViaRole:  res.ViaRole,
					Severity: string(res.Severity),
				})
				if res.Severity == graph.SeverityCritical {
					riskFactors = append(riskFactors, riskFactor{
						Category:    "Critical Access",
						Description: fmt.Sprintf("Can access %s with %v", res.Resource.Name, res.Verbs),
						Severity:    "critical",
					})
				}
			}

			if isOverpriv {
				overprivilegedCount++
			}

			usedBy := saInUse[result.ServiceAccount.ID]

			nodes = append(nodes, htmlNode{
				ID:               result.ServiceAccount.ID,
				Name:             result.ServiceAccount.Name,
				Type:             "serviceaccount",
				Namespace:        result.ServiceAccount.Namespace,
				Risk:             saRisk,
				RiskScore:        severityScore(result.MaxSeverity),
				Layer:            1,
				CloudARN:         result.ServiceAccount.Metadata.CloudRoleARN,
				InUse:            len(usedBy) > 0,
				IsOverprivileged: isOverpriv,
				TotalPerms:       result.TotalK8sPerms,
				RiskFactors:      riskFactors,
				Permissions:      perms,
				UsedBy:           usedBy,
			})

			if len(usedBy) == 0 {
				unusedSA++
			}
		}

		if result.SourceWorkload != nil && result.ServiceAccount != nil {
			linkKey := result.SourceWorkload.ID + "->" + result.ServiceAccount.ID
			if !linksSeen[linkKey] {
				linksSeen[linkKey] = true
				links = append(links, htmlLink{
					Source: result.SourceWorkload.ID,
					Target: result.ServiceAccount.ID,
					Type:   "uses",
					Risk:   "info",
					Label:  "uses",
					Value:  1,
				})
			}
		}

		for _, access := range result.K8sResources {
			roleID := "role:" + access.ViaRole
			if !nodesSeen[roleID] {
				nodesSeen[roleID] = true
				nodes = append(nodes, htmlNode{
					ID:        roleID,
					Name:      access.ViaRole,
					Type:      "role",
					Risk:      "medium",
					RiskScore: 50,
					Layer:     2,
				})
			}

			if result.ServiceAccount != nil {
				linkKey := result.ServiceAccount.ID + "->" + roleID
				if !linksSeen[linkKey] {
					linksSeen[linkKey] = true
					links = append(links, htmlLink{
						Source: result.ServiceAccount.ID,
						Target: roleID,
						Type:   "binds",
						Risk:   "info",
						Label:  "binds",
						Value:  2,
					})
				}
			}

			resourceID := access.Resource.ID
			if !nodesSeen[resourceID] {
				nodesSeen[resourceID] = true
				nodes = append(nodes, htmlNode{
					ID:        resourceID,
					Name:      access.Resource.Name,
					Type:      "resource",
					Namespace: access.Resource.Namespace,
					Risk:      string(access.Severity),
					RiskScore: severityScore(access.Severity),
					Layer:     3,
					Kind:      access.Resource.Metadata.ResourceKind,
					Verbs:     access.Verbs,
				})

				if access.Severity == graph.SeverityCritical {
					criticalCount++
				} else if access.Severity == graph.SeverityHigh {
					highCount++
				}
			}

			linkKey := roleID + "->" + resourceID
			if !linksSeen[linkKey] {
				linksSeen[linkKey] = true
				links = append(links, htmlLink{
					Source: roleID,
					Target: resourceID,
					Type:   "grants",
					Risk:   string(access.Severity),
					Label:  formatVerbs(access.Verbs),
					Verbs:  access.Verbs,
					Value:  severityScore(access.Severity) / 20,
				})
			}
		}

		for _, access := range result.CloudRoles {
			cloudID := "cloud:" + sanitizeCloudID(access.RoleARN)
			if !nodesSeen[cloudID] {
				nodesSeen[cloudID] = true

				policies := make([]cloudPolicy, 0)
				for _, p := range access.Policies {
					policies = append(policies, cloudPolicy{
						Name:     p.Name,
						Actions:  p.Actions,
						IsAdmin:  p.IsAdmin,
						Severity: string(p.Severity),
					})
				}

				nodes = append(nodes, htmlNode{
					ID:            cloudID,
					Name:          shortARN(access.RoleARN),
					Type:          "cloudrole",
					Risk:          "high",
					RiskScore:     80,
					Layer:         4,
					CloudARN:      access.RoleARN,
					Kind:          access.Provider,
					CloudPolicies: policies,
					BlastRadius:   access.BlastRadius,
				})
				cloudCount++
			}

			if result.ServiceAccount != nil {
				linkKey := result.ServiceAccount.ID + "->" + cloudID
				if !linksSeen[linkKey] {
					linksSeen[linkKey] = true
					links = append(links, htmlLink{
						Source: result.ServiceAccount.ID,
						Target: cloudID,
						Type:   "assumes",
						Risk:   "high",
						Label:  "assumes",
						Value:  4,
					})
				}
			}
		}
	}

	return htmlGraph{
		Nodes: nodes,
		Links: links,
		Meta: htmlMeta{
			Title:            fmt.Sprintf("Identity Exposure - %d Workloads", len(results)),
			GeneratedAt:      time.Now().Format(time.RFC3339),
			TotalNodes:       len(nodes),
			TotalLinks:       len(links),
			CriticalCount:    criticalCount,
			HighCount:        highCount,
			CloudRoles:       cloudCount,
			OverprivilegedSA: overprivilegedCount,
			TotalSA:          totalSA,
			UnusedSA:         unusedSA,
		},
	}
}

func (h *HTMLWriter) buildFullGraph(g *graph.Graph) htmlGraph {
	nodes := make([]htmlNode, 0)
	links := make([]htmlLink, 0)

	for _, node := range g.AllNodes() {
		nodeType := string(node.Type)
		risk := "info"
		riskScore := 10

		switch node.Type {
		case graph.NodeWorkload:
			nodeType = "workload"
		case graph.NodeServiceAccount:
			nodeType = "serviceaccount"
			if node.HasCloudIdentity() {
				risk = "high"
				riskScore = 70
			}
		case graph.NodeRole:
			nodeType = "role"
			risk = "medium"
			riskScore = 50
		case graph.NodeK8sResource:
			nodeType = "resource"
			if node.Metadata.ResourceKind == "secrets" {
				risk = "critical"
				riskScore = 100
			}
		case graph.NodeCloudRole:
			nodeType = "cloudrole"
			risk = "high"
			riskScore = 80
		case graph.NodeCloudResource:
			nodeType = "resource"
			risk = "high"
			riskScore = 75
		}

		nodes = append(nodes, htmlNode{
			ID:        node.ID,
			Name:      node.Name,
			Type:      nodeType,
			Namespace: node.Namespace,
			Risk:      risk,
			RiskScore: riskScore,
			Layer:     getLayer(nodeType),
			Kind:      node.Metadata.WorkloadKind,
			CloudARN:  node.Metadata.CloudRoleARN,
		})
	}

	for _, edge := range g.AllEdges() {
		risk := "info"
		value := 1

		switch edge.Type {
		case graph.EdgeGrants:
			for _, v := range edge.Metadata.Verbs {
				if v == "*" || v == "delete" {
					risk = "high"
					value = 4
					break
				}
			}
		case graph.EdgeAssumes:
			risk = "high"
			value = 4
		case graph.EdgeAllows:
			risk = "high"
			value = 4
		}

		links = append(links, htmlLink{
			Source: edge.From,
			Target: edge.To,
			Type:   string(edge.Type),
			Risk:   risk,
			Label:  formatVerbs(edge.Metadata.Verbs),
			Verbs:  edge.Metadata.Verbs,
			Value:  value,
		})
	}

	stats := g.Stats()
	return htmlGraph{
		Nodes: nodes,
		Links: links,
		Meta: htmlMeta{
			Title:       "Identity Chain Graph",
			GeneratedAt: time.Now().Format(time.RFC3339),
			TotalNodes:  stats.TotalNodes,
			TotalLinks:  stats.TotalEdges,
		},
	}
}

func (h *HTMLWriter) renderHTML(hg htmlGraph) error {
	jsonData, err := json.Marshal(hg)
	if err != nil {
		return err
	}

	html := fmt.Sprintf(htmlTemplate,
		hg.Meta.Title,
		hg.Meta.Title,
		hg.Meta.CriticalCount,
		hg.Meta.HighCount,
		hg.Meta.CloudRoles,
		hg.Meta.OverprivilegedSA,
		hg.Meta.TotalSA,
		string(jsonData))

	_, err = h.w.Write([]byte(html))
	return err
}

func severityScore(s graph.Severity) int {
	switch s {
	case graph.SeverityCritical:
		return 100
	case graph.SeverityHigh:
		return 75
	case graph.SeverityMedium:
		return 50
	case graph.SeverityLow:
		return 25
	default:
		return 10
	}
}

func formatVerbs(verbs []string) string {
	if len(verbs) == 0 {
		return ""
	}
	if len(verbs) > 3 {
		return fmt.Sprintf("%s +%d", verbs[0], len(verbs)-1)
	}
	return strings.Join(verbs, ", ")
}

func sanitizeCloudID(s string) string {
	s = strings.ReplaceAll(s, ":", "_")
	s = strings.ReplaceAll(s, "/", "_")
	return s
}

func escapeForJSON(s string) string {
	s = html.EscapeString(s)
	s = strings.ReplaceAll(s, "\\", "\\\\")
	s = strings.ReplaceAll(s, "\"", "\\\"")
	s = strings.ReplaceAll(s, "\n", "\\n")
	s = strings.ReplaceAll(s, "\r", "\\r")
	s = strings.ReplaceAll(s, "\t", "\\t")
	return s
}

func describeK8sResourceAccess(resourceName, namespace string, verbs []string, severity graph.Severity) string {
	hasRead := false
	hasWrite := false
	hasDelete := false
	hasAll := false

	for _, v := range verbs {
		switch v {
		case "*":
			hasAll = true
		case "get", "list", "watch":
			hasRead = true
		case "create", "update", "patch":
			hasWrite = true
		case "delete", "deletecollection":
			hasDelete = true
		}
	}

	scope := namespace
	if scope == "" {
		scope = "cluster-wide"
	}

	var accessLevel string
	if hasAll {
		accessLevel = "FULL control"
	} else if hasWrite && hasDelete {
		accessLevel = "Read/Write/Delete"
	} else if hasWrite {
		accessLevel = "Read/Write"
	} else if hasDelete {
		accessLevel = "Read/Delete"
	} else if hasRead {
		accessLevel = "Read"
	} else {
		accessLevel = strings.Join(verbs, ", ")
	}

	switch resourceName {
	case "secrets":
		if hasAll || hasRead {
			return fmt.Sprintf("Can READ ALL SECRETS in %s - potential credential exposure", scope)
		}
		return fmt.Sprintf("%s access to secrets in %s", accessLevel, scope)
	case "configmaps":
		return fmt.Sprintf("%s access to ConfigMaps in %s", accessLevel, scope)
	case "pods":
		if hasAll || hasWrite {
			return fmt.Sprintf("Can CREATE/MODIFY PODS in %s - potential container injection", scope)
		}
		return fmt.Sprintf("%s access to pods in %s", accessLevel, scope)
	case "pods/exec":
		if hasWrite || hasAll {
			return fmt.Sprintf("Can EXEC INTO PODS in %s - lateral movement risk", scope)
		}
		return fmt.Sprintf("Pod exec access in %s", scope)
	case "deployments", "daemonsets", "statefulsets", "replicasets":
		if hasWrite || hasAll {
			return fmt.Sprintf("Can modify %s in %s - potential workload takeover", resourceName, scope)
		}
		return fmt.Sprintf("%s access to %s in %s", accessLevel, resourceName, scope)
	case "services", "endpoints":
		if hasWrite || hasAll {
			return fmt.Sprintf("Can modify %s in %s - potential traffic hijacking", resourceName, scope)
		}
		return fmt.Sprintf("%s access to %s in %s", accessLevel, resourceName, scope)
	case "roles", "clusterroles", "rolebindings", "clusterrolebindings":
		if hasWrite || hasAll {
			return fmt.Sprintf("Can MODIFY RBAC %s - PRIVILEGE ESCALATION RISK", resourceName)
		}
		return fmt.Sprintf("%s access to RBAC %s", accessLevel, resourceName)
	case "serviceaccounts":
		if hasWrite || hasAll {
			return fmt.Sprintf("Can create/modify ServiceAccounts in %s - identity manipulation risk", scope)
		}
		return fmt.Sprintf("%s access to ServiceAccounts in %s", accessLevel, scope)
	case "nodes":
		if hasAll || hasWrite {
			return "Can modify NODES - cluster infrastructure risk"
		}
		return fmt.Sprintf("%s access to nodes", accessLevel)
	case "persistentvolumes", "persistentvolumeclaims":
		return fmt.Sprintf("%s access to storage (%s)", accessLevel, resourceName)
	case "namespaces":
		if hasWrite || hasAll {
			return "Can create/modify namespaces - tenant isolation risk"
		}
		return fmt.Sprintf("%s access to namespaces", accessLevel)
	default:
		if severity == graph.SeverityCritical {
			return fmt.Sprintf("CRITICAL: %s access to %s in %s", accessLevel, resourceName, scope)
		}
		return fmt.Sprintf("%s access to %s in %s", accessLevel, resourceName, scope)
	}
}

const htmlTemplate = `<!DOCTYPE html>
<html>
<head>
  <meta charset="utf-8">
  <title>%s - Identity Exposure</title>
  <script src="https://d3js.org/d3.v7.min.js"></script>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body { font-family: 'Inter', -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; background: linear-gradient(135deg, #0c0f1a 0%%, #1a1f35 100%%); color: #e2e8f0; min-height: 100vh; overflow: hidden; }
    #container { display: flex; height: 100vh; }
    #sidebar { width: 340px; background: rgba(15, 20, 35, 0.95); backdrop-filter: blur(20px); border-right: 1px solid rgba(99, 102, 241, 0.2); padding: 24px; overflow-y: auto; flex-shrink: 0; }
    #graph { flex: 1; position: relative; }
    svg { width: 100%%; height: 100%%; }

    .header { margin-bottom: 28px; }
    .header h1 { font-size: 22px; font-weight: 700; background: linear-gradient(135deg, #60a5fa, #a78bfa); -webkit-background-clip: text; -webkit-text-fill-color: transparent; margin-bottom: 8px; }
    .header .subtitle { font-size: 13px; color: #64748b; line-height: 1.6; }
    .header .target { font-size: 14px; color: #60a5fa; font-weight: 600; margin-top: 12px; padding: 12px 16px; background: rgba(96, 165, 250, 0.1); border-radius: 10px; border-left: 4px solid #60a5fa; }

    .risk-banner { background: linear-gradient(135deg, rgba(239, 68, 68, 0.15) 0%%, rgba(249, 115, 22, 0.15) 100%%); border: 1px solid rgba(239, 68, 68, 0.3); border-radius: 16px; padding: 20px; margin-bottom: 24px; }
    .risk-banner-title { font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: #f87171; margin-bottom: 16px; display: flex; align-items: center; gap: 8px; }
    .risk-banner-title::before { content: '⚠'; font-size: 16px; }
    .risk-grid { display: grid; grid-template-columns: repeat(2, 1fr); gap: 12px; }
    .risk-item { background: rgba(0, 0, 0, 0.3); border-radius: 12px; padding: 16px; text-align: center; }
    .risk-value { font-size: 32px; font-weight: 800; }
    .risk-value.critical { color: #f87171; }
    .risk-value.high { color: #fb923c; }
    .risk-value.cloud { color: #a78bfa; }
    .risk-value.overpriv { color: #f472b6; }
    .risk-label { font-size: 11px; color: #94a3b8; margin-top: 4px; text-transform: uppercase; letter-spacing: 0.5px; }

    .section { margin-bottom: 24px; }
    .section-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1.5px; color: #64748b; margin-bottom: 14px; display: flex; align-items: center; gap: 10px; }
    .section-title::before { content: ''; width: 4px; height: 16px; background: linear-gradient(180deg, #6366f1, #8b5cf6); border-radius: 2px; }

    .legend-item { display: flex; align-items: center; gap: 14px; padding: 12px; margin-bottom: 8px; background: rgba(30, 41, 59, 0.5); border-radius: 12px; border: 1px solid rgba(51, 65, 85, 0.5); transition: all 0.2s; cursor: pointer; }
    .legend-item:hover { background: rgba(99, 102, 241, 0.1); border-color: rgba(99, 102, 241, 0.3); }
    .legend-icon { width: 44px; height: 44px; border-radius: 12px; display: flex; align-items: center; justify-content: center; }
    .legend-icon svg { width: 28px; height: 28px; }
    .legend-text { flex: 1; }
    .legend-name { font-size: 13px; font-weight: 600; color: #f1f5f9; }
    .legend-count { font-size: 11px; color: #64748b; margin-top: 2px; }

    .node { cursor: pointer; }
    .node-bg { filter: drop-shadow(0 4px 12px rgba(0,0,0,0.3)); }
    .node-inner { pointer-events: none; }
    .node-inner path, .node-inner rect, .node-inner circle { pointer-events: none; }
    .node-label { font-size: 11px; fill: #94a3b8; font-weight: 600; text-anchor: middle; pointer-events: none; }
    .node-badge { font-size: 10px; fill: #fff; font-weight: 700; pointer-events: none; }
    .node-badge-circle { pointer-events: none; }
    .node-unused-rect { pointer-events: none; }
    .node-unused-text { pointer-events: none; }

    .link { fill: none; stroke-linecap: round; opacity: 0.6; }
    .link:hover { opacity: 1; }

    .layer-label { font-size: 13px; fill: rgba(100, 116, 139, 0.8); text-transform: uppercase; letter-spacing: 3px; font-weight: 700; }

    #detail-panel { position: fixed; top: 0; right: -450px; width: 450px; height: 100vh; background: rgba(15, 20, 35, 0.98); backdrop-filter: blur(20px); border-left: 1px solid rgba(99, 102, 241, 0.2); transition: right 0.3s ease; z-index: 2000; overflow-y: auto; }
    #detail-panel.open { right: 0; }

    .panel-header { padding: 24px; border-bottom: 1px solid rgba(51, 65, 85, 0.5); position: sticky; top: 0; background: rgba(15, 20, 35, 0.98); z-index: 10; }
    .panel-header-top { display: flex; align-items: flex-start; gap: 16px; }
    .panel-close { background: none; border: none; color: #64748b; cursor: pointer; padding: 8px; border-radius: 8px; font-size: 20px; margin-left: auto; }
    .panel-close:hover { background: rgba(248, 113, 113, 0.1); color: #f87171; }
    .panel-icon { width: 56px; height: 56px; border-radius: 16px; display: flex; align-items: center; justify-content: center; }
    .panel-icon svg { width: 32px; height: 32px; }
    .panel-title-area { flex: 1; }
    .panel-title { font-size: 18px; font-weight: 700; color: #f1f5f9; margin-bottom: 4px; }
    .panel-subtitle { font-size: 13px; color: #64748b; }

    .panel-content { padding: 24px; }

    .panel-risk-badge { display: inline-flex; align-items: center; gap: 6px; padding: 8px 16px; border-radius: 20px; font-size: 12px; font-weight: 700; text-transform: uppercase; letter-spacing: 0.5px; margin: 16px 0; }
    .panel-risk-badge.critical { background: rgba(239, 68, 68, 0.15); color: #f87171; border: 1px solid rgba(239, 68, 68, 0.3); }
    .panel-risk-badge.high { background: rgba(249, 115, 22, 0.15); color: #fb923c; border: 1px solid rgba(249, 115, 22, 0.3); }
    .panel-risk-badge.medium { background: rgba(234, 179, 8, 0.15); color: #facc15; border: 1px solid rgba(234, 179, 8, 0.3); }
    .panel-risk-badge.low { background: rgba(34, 197, 94, 0.15); color: #4ade80; border: 1px solid rgba(34, 197, 94, 0.3); }

    .panel-section { margin-bottom: 24px; }
    .panel-section-title { font-size: 11px; font-weight: 700; text-transform: uppercase; letter-spacing: 1px; color: #64748b; margin-bottom: 12px; display: flex; align-items: center; gap: 8px; }

    .risk-factor { background: rgba(239, 68, 68, 0.08); border: 1px solid rgba(239, 68, 68, 0.2); border-radius: 12px; padding: 14px; margin-bottom: 10px; }
    .risk-factor.high { background: rgba(249, 115, 22, 0.08); border-color: rgba(249, 115, 22, 0.2); }
    .risk-factor-header { display: flex; align-items: center; gap: 8px; margin-bottom: 6px; }
    .risk-factor-icon { font-size: 14px; }
    .risk-factor-category { font-size: 12px; font-weight: 700; color: #f87171; }
    .risk-factor.high .risk-factor-category { color: #fb923c; }
    .risk-factor-desc { font-size: 12px; color: #94a3b8; line-height: 1.5; }

    .perm-item { background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(51, 65, 85, 0.5); border-radius: 10px; padding: 12px; margin-bottom: 8px; }
    .perm-header { display: flex; align-items: center; justify-content: space-between; margin-bottom: 8px; }
    .perm-resource { font-size: 13px; font-weight: 600; color: #f1f5f9; }
    .perm-severity { font-size: 10px; padding: 3px 8px; border-radius: 6px; font-weight: 600; text-transform: uppercase; }
    .perm-severity.critical { background: rgba(239, 68, 68, 0.15); color: #f87171; }
    .perm-severity.high { background: rgba(249, 115, 22, 0.15); color: #fb923c; }
    .perm-severity.medium { background: rgba(234, 179, 8, 0.15); color: #facc15; }
    .perm-severity.low { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
    .perm-verbs { display: flex; flex-wrap: wrap; gap: 6px; }
    .perm-verb { font-size: 11px; padding: 4px 10px; background: rgba(99, 102, 241, 0.15); color: #a5b4fc; border-radius: 6px; font-weight: 500; }
    .perm-role { font-size: 11px; color: #64748b; margin-top: 8px; }

    .usage-badge { display: inline-flex; align-items: center; gap: 6px; padding: 6px 12px; border-radius: 8px; font-size: 11px; font-weight: 600; }
    .usage-badge.in-use { background: rgba(34, 197, 94, 0.15); color: #4ade80; }
    .usage-badge.unused { background: rgba(251, 146, 60, 0.15); color: #fb923c; }

    .used-by-item { background: rgba(30, 41, 59, 0.5); border: 1px solid rgba(51, 65, 85, 0.5); border-radius: 8px; padding: 10px 14px; margin-bottom: 6px; font-size: 12px; color: #e2e8f0; display: flex; align-items: center; gap: 8px; }
    .used-by-icon { width: 20px; height: 20px; }

    @keyframes pulse { 0%%, 100%% { opacity: 1; } 50%% { opacity: 0.5; } }
    @keyframes flowParticle { 0%% { offset-distance: 0%%; opacity: 0; } 10%% { opacity: 1; } 90%% { opacity: 1; } 100%% { offset-distance: 100%%; opacity: 0; } }

    #controls { position: absolute; bottom: 24px; left: 50%%; transform: translateX(-50%%); display: flex; gap: 8px; background: rgba(15, 20, 35, 0.9); backdrop-filter: blur(10px); padding: 8px; border-radius: 14px; border: 1px solid rgba(99, 102, 241, 0.2); }
    #controls button { background: transparent; border: none; color: #94a3b8; padding: 10px 18px; border-radius: 10px; cursor: pointer; font-size: 13px; font-weight: 600; transition: all 0.2s; }
    #controls button:hover { background: rgba(99, 102, 241, 0.15); color: #e2e8f0; }
    #controls button.active { background: linear-gradient(135deg, #6366f1, #8b5cf6); color: #fff; }
  </style>
</head>
<body>
  <div id="container">
    <div id="sidebar">
      <div class="header">
        <h1>Identity Exposure</h1>
        <div class="subtitle">Analyze identity chains and blast radius for Kubernetes workloads</div>
        <div class="target">%s</div>
      </div>

      <div class="risk-banner">
        <div class="risk-banner-title">Exposure Summary</div>
        <div class="risk-grid">
          <div class="risk-item"><div class="risk-value critical">%d</div><div class="risk-label">Critical</div></div>
          <div class="risk-item"><div class="risk-value high">%d</div><div class="risk-label">High Risk</div></div>
          <div class="risk-item"><div class="risk-value cloud">%d</div><div class="risk-label">Cloud Roles</div></div>
          <div class="risk-item"><div class="risk-value overpriv">%d/%d</div><div class="risk-label">Overprivileged SA</div></div>
        </div>
      </div>

      <div class="section">
        <div class="section-title">Identity Types</div>
        <div id="legend"></div>
      </div>
    </div>
    <div id="graph">
      <div id="controls">
        <button onclick="showAll()" class="active">All</button>
        <button onclick="filterType('serviceaccount')">Service Accounts</button>
        <button onclick="filterRisk('critical')">Critical</button>
        <button onclick="filterOverpriv()">Overprivileged</button>
      </div>
    </div>
  </div>

  <div id="detail-panel">
    <div class="panel-header">
      <div class="panel-header-top">
        <div class="panel-icon" id="panel-icon"></div>
        <div class="panel-title-area">
          <div class="panel-title" id="panel-title"></div>
          <div class="panel-subtitle" id="panel-subtitle"></div>
        </div>
        <button class="panel-close" onclick="closePanel()">✕</button>
      </div>
    </div>
    <div class="panel-content" id="panel-content"></div>
  </div>

  <script>
const data = %s;
const container = document.getElementById('graph');
const width = container.clientWidth;
const height = container.clientHeight;

const iconDefs = {
  workload: { bg: 'linear-gradient(135deg, #3b82f6, #1d4ed8)', icon: '<rect x="6" y="6" width="12" height="12" rx="2" fill="rgba(255,255,255,0.9)"/><rect x="22" y="6" width="12" height="12" rx="2" fill="rgba(255,255,255,0.9)"/><rect x="6" y="22" width="12" height="12" rx="2" fill="rgba(255,255,255,0.9)"/><rect x="22" y="22" width="12" height="12" rx="2" fill="rgba(255,255,255,0.9)"/>' },
  serviceaccount: { bg: 'linear-gradient(135deg, #10b981, #059669)', icon: '<circle cx="20" cy="12" r="8" fill="rgba(255,255,255,0.9)"/><path d="M6 36c0-7.732 6.268-14 14-14s14 6.268 14 36" fill="rgba(255,255,255,0.9)"/>' },
  role: { bg: 'linear-gradient(135deg, #f59e0b, #d97706)', icon: '<path d="M20 4L36 12V28L20 36L4 28V12L20 4Z" fill="rgba(255,255,255,0.2)" stroke="rgba(255,255,255,0.9)" stroke-width="2"/><circle cx="20" cy="20" r="6" fill="rgba(255,255,255,0.9)"/>' },
  resource: { bg: 'linear-gradient(135deg, #ec4899, #be185d)', icon: '<rect x="6" y="8" width="28" height="24" rx="3" fill="rgba(255,255,255,0.9)"/><rect x="10" y="14" width="16" height="2" rx="1" fill="currentColor" opacity="0.3"/><rect x="10" y="20" width="12" height="2" rx="1" fill="currentColor" opacity="0.3"/><rect x="10" y="26" width="8" height="2" rx="1" fill="currentColor" opacity="0.3"/>' },
  cloudrole: { bg: 'linear-gradient(135deg, #8b5cf6, #6d28d9)', icon: '<path d="M20 6c-5 0-9 3.5-10 8-4 1-7 4.5-7 8.5C3 28 7.5 32 13 32h16c4 0 8-3.5 8-8 0-3.5-2.5-6.5-6-7.5C31 10.5 26 6 20 6z" fill="rgba(255,255,255,0.9)"/>' }
};

const typeLabels = { workload: 'Workloads', serviceaccount: 'Service Accounts', role: 'Roles', resource: 'Resources', cloudrole: 'Cloud Roles' };
const typeCounts = {};
data.nodes.forEach(n => typeCounts[n.type] = (typeCounts[n.type] || 0) + 1);

const legendEl = document.getElementById('legend');
['workload', 'serviceaccount', 'role', 'resource', 'cloudrole'].filter(t => typeCounts[t]).forEach(type => {
  const def = iconDefs[type];
  legendEl.innerHTML += '<div class="legend-item" onclick="filterType(\'' + type + '\')"><div class="legend-icon" style="background:' + def.bg + '"><svg viewBox="0 0 40 40">' + def.icon + '</svg></div><div class="legend-text"><div class="legend-name">' + typeLabels[type] + '</div><div class="legend-count">' + typeCounts[type] + ' nodes</div></div></div>';
});

const layerNames = {0:'Workloads',1:'Identities',2:'Permissions',3:'Resources',4:'Cloud'};
const usedLayers = [...new Set(data.nodes.map(n => n.layer))].sort((a,b)=>a-b);
const layerSpacing = Math.min(240, (width - 300) / Math.max(usedLayers.length, 1));
const startX = 180;
const layerX = {};
usedLayers.forEach((l, i) => layerX[l] = startX + i * layerSpacing);

const nodesByLayer = {};
data.nodes.forEach(n => { if(!nodesByLayer[n.layer]) nodesByLayer[n.layer]=[]; nodesByLayer[n.layer].push(n); });
Object.keys(nodesByLayer).forEach(layer => {
  const nodes = nodesByLayer[layer];
  const spacing = Math.min(90, (height - 160) / Math.max(nodes.length, 1));
  const startY = (height - (nodes.length - 1) * spacing) / 2;
  nodes.forEach((n, i) => { n.x = layerX[n.layer] || width/2; n.y = startY + i * spacing; });
});

const nodeMap = {}; data.nodes.forEach(n => nodeMap[n.id] = n);

const svg = d3.select('#graph').append('svg');
const defs = svg.append('defs');

const glow = defs.append('filter').attr('id','glow').attr('x','-50%%').attr('y','-50%%').attr('width','200%%').attr('height','200%%');
glow.append('feGaussianBlur').attr('stdDeviation','6').attr('result','blur');
glow.append('feMerge').html('<feMergeNode in="blur"/><feMergeNode in="SourceGraphic"/>');

const critGlow = defs.append('filter').attr('id','crit-glow').attr('x','-50%%').attr('y','-50%%').attr('width','200%%').attr('height','200%%');
critGlow.append('feGaussianBlur').attr('stdDeviation','8').attr('result','blur');
critGlow.append('feFlood').attr('flood-color','#ef4444').attr('flood-opacity','0.5');
critGlow.append('feComposite').attr('in2','blur').attr('operator','in');
critGlow.append('feMerge').html('<feMergeNode/><feMergeNode in="SourceGraphic"/>');

defs.append('marker').attr('id','arrow').attr('viewBox','0 -5 10 10').attr('refX',32).attr('refY',0).attr('markerWidth',8).attr('markerHeight',8).attr('orient','auto')
  .append('path').attr('d','M0,-4L10,0L0,4').attr('fill','#6366f1');
defs.append('marker').attr('id','arrow-crit').attr('viewBox','0 -5 10 10').attr('refX',32).attr('refY',0).attr('markerWidth',8).attr('markerHeight',8).attr('orient','auto')
  .append('path').attr('d','M0,-4L10,0L0,4').attr('fill','#ef4444');
defs.append('marker').attr('id','arrow-high').attr('viewBox','0 -5 10 10').attr('refX',32).attr('refY',0).attr('markerWidth',8).attr('markerHeight',8).attr('orient','auto')
  .append('path').attr('d','M0,-4L10,0L0,4').attr('fill','#f97316');

const gradients = [
  {id:'grad-workload', c1:'#3b82f6', c2:'#1d4ed8'},
  {id:'grad-serviceaccount', c1:'#10b981', c2:'#059669'},
  {id:'grad-role', c1:'#f59e0b', c2:'#d97706'},
  {id:'grad-resource', c1:'#ec4899', c2:'#be185d'},
  {id:'grad-cloudrole', c1:'#8b5cf6', c2:'#6d28d9'},
  {id:'grad-critical', c1:'#ef4444', c2:'#b91c1c'},
  {id:'grad-high', c1:'#f97316', c2:'#c2410c'}
];
gradients.forEach(g => {
  const grad = defs.append('linearGradient').attr('id',g.id).attr('x1','0%%').attr('y1','0%%').attr('x2','100%%').attr('y2','100%%');
  grad.append('stop').attr('offset','0%%').attr('stop-color',g.c1);
  grad.append('stop').attr('offset','100%%').attr('stop-color',g.c2);
});

const g = svg.append('g');
const zoom = d3.zoom().scaleExtent([0.3,3]).on('zoom',e=>g.attr('transform',e.transform));
svg.call(zoom);

Object.entries(layerX).forEach(([layer, x]) => {
  if(nodesByLayer[layer] && layerNames[layer]) {
    g.append('text').attr('class','layer-label').attr('x',x).attr('y',40).attr('text-anchor','middle').text(layerNames[layer]);
  }
});

const linkG = g.append('g');
const validLinks = data.links.filter(l => nodeMap[l.source] && nodeMap[l.target]);
const links = linkG.selectAll('path').data(validLinks).join('path')
  .attr('class','link')
  .attr('stroke', d => d.risk==='critical'?'#ef4444':d.risk==='high'?'#f97316':'#6366f1')
  .attr('stroke-width', d => d.risk==='critical'?3:d.risk==='high'?2.5:2)
  .attr('marker-end', d => d.risk==='critical'?'url(#arrow-crit)':d.risk==='high'?'url(#arrow-high)':'url(#arrow)')
  .attr('d', d => {
    const s=nodeMap[d.source], t=nodeMap[d.target];
    const dx = t.x - s.x, dy = t.y - s.y;
    return 'M'+s.x+','+s.y+' Q'+(s.x+dx*0.5)+','+(s.y)+' '+t.x+','+t.y;
  });

const nodeG = g.append('g');
const nodes = nodeG.selectAll('g').data(data.nodes).join('g')
  .attr('class','node')
  .attr('filter', d => d.risk==='critical'?'url(#crit-glow)':d.isOverprivileged?'url(#glow)':'none')
  .attr('transform', d => 'translate('+(d.x-28)+','+(d.y-28)+')');

nodes.each(function(d) {
  const node = d3.select(this);
  const def = iconDefs[d.type] || iconDefs.resource;
  const size = d.type === 'serviceaccount' ? 56 : 48;
  const offset = d.type === 'serviceaccount' ? 0 : 4;

  const bg = node.append('g').attr('class','node-bg').attr('transform','translate('+(offset+size/2)+','+(offset+size/2)+')');

  bg.append('rect')
    .attr('class','node-icon')
    .attr('x', -size/2).attr('y', -size/2)
    .attr('width', size).attr('height', size)
    .attr('rx', 14)
    .attr('fill', d.risk==='critical'?'url(#grad-critical)':d.risk==='high'?'url(#grad-high)':'url(#grad-'+d.type+')');

  bg.append('g')
    .attr('class','node-inner')
    .attr('transform', 'translate(-20,-20)')
    .html(def.icon);

  if (d.isOverprivileged || d.risk === 'critical' || d.risk === 'high') {
    node.append('circle').attr('class','node-badge-circle').attr('cx', size+offset-4).attr('cy', offset+4).attr('r', 10).attr('fill', d.risk==='critical'?'#ef4444':'#f97316');
    node.append('text').attr('class','node-badge').attr('x', size+offset-4).attr('y', offset+8).attr('text-anchor','middle').text('!');
  }

  if (d.type === 'serviceaccount' && !d.inUse) {
    node.append('rect').attr('class','node-unused-rect').attr('x', offset).attr('y', size+offset+4).attr('width', size).attr('height', 16).attr('rx', 4).attr('fill', 'rgba(251, 146, 60, 0.8)');
    node.append('text').attr('class','node-unused-text').attr('x', offset+size/2).attr('y', size+offset+14).attr('text-anchor','middle').attr('font-size','9').attr('fill','#fff').attr('font-weight','600').text('UNUSED');
  }
});

nodes.append('text')
  .attr('class','node-label')
  .attr('x', 28).attr('y', 72)
  .text(d => d.name.length > 18 ? d.name.slice(0,18)+'...' : d.name);

nodes.on('click', (e, d) => { e.stopPropagation(); showDetail(d); });
svg.on('click', () => { showAll(); closePanel(); });

function showDetail(node) {
  nodes.style('opacity', 0.15);
  links.style('opacity', 0.08);

  const conn = new Set([node.id]);
  data.links.forEach(l => { if(l.source===node.id) conn.add(l.target); if(l.target===node.id) conn.add(l.source); });
  nodes.filter(n => conn.has(n.id)).style('opacity', 1);
  links.filter(l => l.source===node.id || l.target===node.id).style('opacity', 0.9);

  const def = iconDefs[node.type] || iconDefs.resource;
  document.getElementById('panel-icon').innerHTML = '<div style="width:56px;height:56px;border-radius:14px;background:' + def.bg + ';display:flex;align-items:center;justify-content:center"><svg viewBox="0 0 40 40" width="32" height="32">' + def.icon + '</svg></div>';
  document.getElementById('panel-title').textContent = node.name;
  document.getElementById('panel-subtitle').textContent = (node.namespace ? node.namespace + ' • ' : '') + node.type + (node.kind ? ' • ' + node.kind : '');

  let html = '<div class="panel-risk-badge ' + node.risk + '">' + node.risk.toUpperCase() + ' RISK</div>';

  if (node.type === 'serviceaccount') {
    html += '<div style="margin-bottom:16px"><span class="usage-badge ' + (node.inUse ? 'in-use' : 'unused') + '">' + (node.inUse ? '✓ In Use' : '⚠ Unused') + '</span>';
    if (node.isOverprivileged) html += ' <span class="usage-badge" style="background:rgba(244,114,182,0.15);color:#f472b6">⚠ Overprivileged</span>';
    html += '</div>';

    if (node.usedBy && node.usedBy.length) {
      html += '<div class="panel-section"><div class="panel-section-title">Used By Workloads</div>';
      node.usedBy.forEach(w => {
        html += '<div class="used-by-item"><svg class="used-by-icon" viewBox="0 0 40 40">' + iconDefs.workload.icon + '</svg>' + w + '</div>';
      });
      html += '</div>';
    }

    if (node.riskFactors && node.riskFactors.length) {
      html += '<div class="panel-section"><div class="panel-section-title">⚠ Risk Factors</div>';
      node.riskFactors.forEach(rf => {
        html += '<div class="risk-factor ' + rf.severity + '"><div class="risk-factor-header"><span class="risk-factor-icon">' + (rf.severity==='critical'?'🔴':'🟠') + '</span><span class="risk-factor-category">' + rf.category + '</span></div><div class="risk-factor-desc">' + rf.description + '</div></div>';
      });
      html += '</div>';
    }

    if (node.permissions && node.permissions.length) {
      html += '<div class="panel-section"><div class="panel-section-title">Permissions (' + node.totalPerms + ' total)</div>';
      node.permissions.slice(0, 10).forEach(p => {
        html += '<div class="perm-item"><div class="perm-header"><span class="perm-resource">' + p.resource + '</span><span class="perm-severity ' + p.severity + '">' + p.severity + '</span></div><div class="perm-verbs">' + p.verbs.map(v => '<span class="perm-verb">' + v + '</span>').join('') + '</div><div class="perm-role">via ' + p.viaRole + '</div></div>';
      });
      if (node.permissions.length > 10) html += '<div style="color:#64748b;font-size:12px;margin-top:8px">... and ' + (node.permissions.length - 10) + ' more</div>';
      html += '</div>';
    }

    if (node.blastRadius && node.blastRadius.length) {
      html += '<div class="panel-section"><div class="panel-section-title">💥 Blast Radius - If Compromised</div>';
      node.blastRadius.forEach(br => {
        const severity = br.includes('SECRETS') || br.includes('CRITICAL') || br.includes('PRIVILEGE') ? 'critical' : (br.includes('EXEC') || br.includes('MODIFY') ? 'high' : 'medium');
        html += '<div class="risk-factor ' + severity + '"><div class="risk-factor-header"><span class="risk-factor-icon">' + (severity==='critical'?'🔴':(severity==='high'?'🟠':'🟡')) + '</span><span class="risk-factor-category">K8s Access</span></div><div class="risk-factor-desc">' + br + '</div></div>';
      });
      html += '</div>';
    }
  }

  if (node.type === 'cloudrole') {
    if (node.blastRadius && node.blastRadius.length) {
      html += '<div class="panel-section"><div class="panel-section-title">⚠ Blast Radius - If Compromised</div>';
      node.blastRadius.forEach(br => {
        html += '<div class="risk-factor critical"><div class="risk-factor-header"><span class="risk-factor-icon">💥</span><span class="risk-factor-category">Cloud Access</span></div><div class="risk-factor-desc">' + br + '</div></div>';
      });
      html += '</div>';
    }

    if (node.cloudPolicies && node.cloudPolicies.length) {
      html += '<div class="panel-section"><div class="panel-section-title">Attached Policies</div>';
      node.cloudPolicies.forEach(p => {
        html += '<div class="perm-item"><div class="perm-header"><span class="perm-resource">' + p.name + '</span>';
        if (p.isAdmin) html += '<span class="perm-severity critical">ADMIN</span>';
        else html += '<span class="perm-severity high">HIGH</span>';
        html += '</div>';
        if (p.actions && p.actions.length) {
          html += '<div class="perm-verbs">' + p.actions.slice(0,5).map(a => '<span class="perm-verb">' + a + '</span>').join('');
          if (p.actions.length > 5) html += '<span class="perm-verb">+' + (p.actions.length - 5) + ' more</span>';
          html += '</div>';
        }
        html += '</div>';
      });
      html += '</div>';
    }
  }

  if (node.cloudArn) {
    html += '<div class="panel-section"><div class="panel-section-title">Cloud Identity ARN</div><div class="perm-item"><div class="perm-resource" style="word-break:break-all;font-family:monospace;font-size:11px">' + node.cloudArn + '</div></div></div>';
  }

  document.getElementById('panel-content').innerHTML = html;
  document.getElementById('detail-panel').classList.add('open');
}

function closePanel() { document.getElementById('detail-panel').classList.remove('open'); }
function showAll() { nodes.style('opacity', 1); links.style('opacity', 0.6); document.querySelectorAll('#controls button').forEach((b,i) => b.classList.toggle('active', i===0)); }
function filterType(type) { nodes.style('opacity', d => d.type===type ? 1 : 0.1); links.style('opacity', l => nodeMap[l.source]?.type===type || nodeMap[l.target]?.type===type ? 0.8 : 0.05); setActiveBtn(1); }
function filterRisk(risk) { nodes.style('opacity', d => d.risk===risk ? 1 : 0.1); links.style('opacity', l => nodeMap[l.source]?.risk===risk || nodeMap[l.target]?.risk===risk ? 0.8 : 0.05); setActiveBtn(2); }
function filterOverpriv() { nodes.style('opacity', d => d.isOverprivileged ? 1 : 0.1); links.style('opacity', 0.05); setActiveBtn(3); }
function setActiveBtn(i) { document.querySelectorAll('#controls button').forEach((b,j) => b.classList.toggle('active', i===j)); }

svg.transition().duration(500).call(zoom.transform, d3.zoomIdentity.translate(40, 0).scale(0.9));
  </script>
</body>
</html>`
