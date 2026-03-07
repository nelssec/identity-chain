package analysis

import (
	"github.com/nelssec/identity-chain/pkg/graph"
)

// ────────────────────────────────────────────────────────────────────────────
// Types
// ────────────────────────────────────────────────────────────────────────────

// OpenShiftAuditOptions configures the OpenShift-specific audit.
type OpenShiftAuditOptions struct {
	IncludeSystem bool
	Namespace     string
}

// OpenShiftFinding is a single security finding from the OpenShift audit.
type OpenShiftFinding struct {
	CheckID     string              `json:"check_id"`
	Title       string              `json:"title"`
	Description string              `json:"description"`
	Severity    graph.Severity      `json:"severity"`
	Affected    []AffectedResource  `json:"affected,omitempty"`
	Remediation string              `json:"remediation,omitempty"`
}

// OpenShiftAuditSummary holds aggregate counts.
type OpenShiftAuditSummary struct {
	TotalFindings    int `json:"total_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings      int `json:"low_findings"`
}

// OpenShiftAuditResult is the top-level return value of RunOpenShiftAudit.
type OpenShiftAuditResult struct {
	IsOpenShift     bool                   `json:"is_openshift"`
	RouteFindings   []OpenShiftFinding     `json:"route_findings,omitempty"`
	OAuthFindings   []OpenShiftFinding     `json:"oauth_findings,omitempty"`
	BuildFindings   []OpenShiftFinding     `json:"build_findings,omitempty"`
	ProjectFindings []OpenShiftFinding     `json:"project_findings,omitempty"`
	RBACFindings    []OpenShiftFinding     `json:"rbac_findings,omitempty"`
	SCCAnalysis     *SCCAnalysisResult     `json:"scc_analysis,omitempty"`
	Summary         OpenShiftAuditSummary  `json:"summary"`
}

// ────────────────────────────────────────────────────────────────────────────
// RunOpenShiftAudit performs a comprehensive OpenShift security audit.
// ────────────────────────────────────────────────────────────────────────────

func RunOpenShiftAudit(g *graph.Graph, opts OpenShiftAuditOptions) *OpenShiftAuditResult {
	result := &OpenShiftAuditResult{}

	// Detect OpenShift by the presence of SCC nodes.
	sccs := g.GetNodesByType(graph.NodeSCC)
	result.IsOpenShift = len(sccs) > 0

	if !result.IsOpenShift {
		return result
	}

	// SCC analysis (reuse existing logic).
	sccResult := AnalyzeSCCs(g)
	result.SCCAnalysis = sccResult

	// Route findings.
	result.RouteFindings = auditRoutes(g, opts)

	// OAuth client findings.
	result.OAuthFindings = auditOAuthClients(g, opts)

	// BuildConfig findings.
	result.BuildFindings = auditBuildConfigs(g, opts)

	// Project findings.
	result.ProjectFindings = auditProjects(g, opts)

	// RBAC findings specific to OpenShift.
	result.RBACFindings = auditOpenShiftRBAC(g, sccResult, opts)

	// Compute summary.
	allFindings := append(result.RouteFindings, result.OAuthFindings...)
	allFindings = append(allFindings, result.BuildFindings...)
	allFindings = append(allFindings, result.ProjectFindings...)
	allFindings = append(allFindings, result.RBACFindings...)
	for _, f := range allFindings {
		result.Summary.TotalFindings++
		switch f.Severity {
		case graph.SeverityCritical:
			result.Summary.CriticalFindings++
		case graph.SeverityHigh:
			result.Summary.HighFindings++
		case graph.SeverityMedium:
			result.Summary.MediumFindings++
		case graph.SeverityLow:
			result.Summary.LowFindings++
		}
	}

	return result
}

// ────────────────────────────────────────────────────────────────────────────
// Individual OpenShift audit sub-checks
// ────────────────────────────────────────────────────────────────────────────

func auditRoutes(g *graph.Graph, opts OpenShiftAuditOptions) []OpenShiftFinding {
	var findings []OpenShiftFinding
	routes := g.GetNodesByType(graph.NodeRoute)

	for _, route := range routes {
		if opts.Namespace != "" && route.Namespace != opts.Namespace {
			continue
		}
		if !opts.IncludeSystem && isSystemNamespace(route.Namespace) {
			continue
		}
		if route.Metadata.RouteInfo == nil {
			continue
		}

		ri := route.Metadata.RouteInfo

		// Insecure route (no TLS).
		if !ri.TLSEnabled {
			findings = append(findings, OpenShiftFinding{
				CheckID:     "OCP-ROUTE-001",
				Title:       "Insecure route without TLS",
				Description: "Route " + route.Name + " does not use TLS encryption",
				Severity:    graph.SeverityMedium,
				Affected:    []AffectedResource{{Kind: "Route", Namespace: route.Namespace, Name: route.Name}},
				Remediation: "Configure TLS termination (edge, passthrough, or reencrypt) for all routes",
			})
		}

		// Allow-all insecure traffic.
		if ri.TLSEnabled && ri.InsecurePolicy == "Allow" {
			findings = append(findings, OpenShiftFinding{
				CheckID:     "OCP-ROUTE-002",
				Title:       "Route allows insecure HTTP traffic",
				Description: "Route " + route.Name + " has insecureEdgeTerminationPolicy: Allow",
				Severity:    graph.SeverityLow,
				Affected:    []AffectedResource{{Kind: "Route", Namespace: route.Namespace, Name: route.Name}},
				Remediation: "Set insecureEdgeTerminationPolicy to Redirect or None",
			})
		}
	}

	return findings
}

func auditOAuthClients(g *graph.Graph, opts OpenShiftAuditOptions) []OpenShiftFinding {
	var findings []OpenShiftFinding
	oauthClients := g.GetNodesByType(graph.NodeOAuthClient)

	for _, client := range oauthClients {
		if client.Metadata.OAuthClientInfo == nil {
			continue
		}
		oi := client.Metadata.OAuthClientInfo

		// Overly long access token lifetime (> 24h = 86400s).
		if oi.AccessTokenMaxAge > 86400 {
			findings = append(findings, OpenShiftFinding{
				CheckID:     "OCP-OAUTH-001",
				Title:       "OAuth client with long-lived access tokens",
				Description: "OAuth client " + client.Name + " has access token max age > 24h",
				Severity:    graph.SeverityMedium,
				Affected:    []AffectedResource{{Kind: "OAuthClient", Name: client.Name}},
				Remediation: "Reduce accessTokenMaxAgeSeconds to 3600 (1 hour) or less",
			})
		}

		// No redirect URIs configured (catch-all).
		if len(oi.RedirectURIs) == 0 {
			findings = append(findings, OpenShiftFinding{
				CheckID:     "OCP-OAUTH-002",
				Title:       "OAuth client with no redirect URIs",
				Description: "OAuth client " + client.Name + " has no redirect URIs configured",
				Severity:    graph.SeverityHigh,
				Affected:    []AffectedResource{{Kind: "OAuthClient", Name: client.Name}},
				Remediation: "Configure explicit redirect URIs for the OAuth client",
			})
		}
	}

	return findings
}

func auditBuildConfigs(g *graph.Graph, opts OpenShiftAuditOptions) []OpenShiftFinding {
	var findings []OpenShiftFinding
	builds := g.GetNodesByType(graph.NodeBuildConfig)

	for _, build := range builds {
		if opts.Namespace != "" && build.Namespace != opts.Namespace {
			continue
		}
		if !opts.IncludeSystem && isSystemNamespace(build.Namespace) {
			continue
		}
		if build.Metadata.BuildConfigInfo == nil {
			continue
		}
		bi := build.Metadata.BuildConfigInfo

		if bi.Privileged {
			findings = append(findings, OpenShiftFinding{
				CheckID:     "OCP-BUILD-001",
				Title:       "Privileged BuildConfig",
				Description: "BuildConfig " + build.Name + " runs with privileged flag set",
				Severity:    graph.SeverityHigh,
				Affected:    []AffectedResource{{Kind: "BuildConfig", Namespace: build.Namespace, Name: build.Name}},
				Remediation: "Remove privileged: true from BuildConfig strategy; use unprivileged build strategies",
			})
		}

		if bi.ExposesDockerSocket {
			findings = append(findings, OpenShiftFinding{
				CheckID:     "OCP-BUILD-002",
				Title:       "BuildConfig exposes Docker socket",
				Description: "BuildConfig " + build.Name + " mounts the Docker socket, enabling container escapes",
				Severity:    graph.SeverityCritical,
				Affected:    []AffectedResource{{Kind: "BuildConfig", Namespace: build.Namespace, Name: build.Name}},
				Remediation: "Switch to Buildah, kaniko, or Source-to-Image builds that do not require the Docker socket",
			})
		}
	}

	return findings
}

func auditProjects(g *graph.Graph, opts OpenShiftAuditOptions) []OpenShiftFinding {
	var findings []OpenShiftFinding
	projects := g.GetNodesByType(graph.NodeProject)

	for _, project := range projects {
		if !opts.IncludeSystem && isSystemNamespace(project.Name) {
			continue
		}
		if project.Metadata.ProjectInfo == nil {
			continue
		}

		pi := project.Metadata.ProjectInfo
		if pi.Status == "Terminating" {
			// Not a security issue but informational; skip.
			continue
		}

		// Projects with no requester (may be system-created or abandoned).
		if pi.Requester == "" {
			findings = append(findings, OpenShiftFinding{
				CheckID:     "OCP-PROJ-001",
				Title:       "Project with no requester annotation",
				Description: "Project " + project.Name + " has no openshift.io/requester annotation",
				Severity:    graph.SeverityLow,
				Affected:    []AffectedResource{{Kind: "Project", Name: project.Name}},
				Remediation: "Ensure projects are created via the project request API so ownership is tracked",
			})
		}
	}

	return findings
}

func auditOpenShiftRBAC(g *graph.Graph, sccResult *SCCAnalysisResult, opts OpenShiftAuditOptions) []OpenShiftFinding {
	var findings []OpenShiftFinding

	// Re-use SCC escalation path data.
	if sccResult != nil {
		for _, path := range sccResult.EscalationPaths {
			if path.RiskLevel == "critical" || path.RiskLevel == "high" {
				findings = append(findings, OpenShiftFinding{
					CheckID:     "OCP-RBAC-001",
					Title:       "SCC escalation path detected",
					Description: path.Description,
					Severity:    graph.SeverityHigh,
					Affected:    []AffectedResource{{Kind: path.SourceType, Name: path.Source}},
					Remediation: "Remove unnecessary SCC bindings; use the most restrictive SCC that meets workload requirements",
				})
			}
		}
	}

	// Check for service accounts that can list all SCCs.
	for _, sa := range g.GetNodesByType(graph.NodeServiceAccount) {
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}
		if !opts.IncludeSystem && isSystemNamespace(sa.Namespace) {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		if canListSCCs(g, roles) {
			findings = append(findings, OpenShiftFinding{
				CheckID:     "OCP-RBAC-002",
				Title:       "ServiceAccount can list SCCs",
				Description: "ServiceAccount " + sa.Namespace + "/" + sa.Name + " can list SecurityContextConstraints",
				Severity:    graph.SeverityMedium,
				Affected:    []AffectedResource{{Kind: "ServiceAccount", Namespace: sa.Namespace, Name: sa.Name}},
				Remediation: "Remove SCC list/get permissions unless strictly required",
			})
		}
	}

	return findings
}

func canListSCCs(g *graph.Graph, roles []*graph.Node) bool {
	for _, role := range roles {
		for _, e := range g.GetOutEdges(role.ID) {
			if e.Type != graph.EdgeGrants {
				continue
			}
			target := g.GetNode(e.To)
			if target == nil {
				continue
			}
			kind := target.Metadata.ResourceKind
			if (kind == "securitycontextconstraints" || kind == "*") &&
				(containsString(e.Metadata.Verbs, "list") ||
					containsString(e.Metadata.Verbs, "get") ||
					containsString(e.Metadata.Verbs, "*")) {
				return true
			}
		}
	}
	return false
}
