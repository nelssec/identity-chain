package analysis

import (
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

// OpenShiftAuditOptions configures the OpenShift-specific audit.
type OpenShiftAuditOptions struct {
	IncludeSystem bool
	Namespace     string
}

// OpenShiftFinding is a single finding from the OpenShift security audit.
type OpenShiftFinding struct {
	CheckID     string                `json:"check_id"`
	Severity    graph.Severity        `json:"severity"`
	Title       string                `json:"title"`
	Description string                `json:"description"`
	Remediation string                `json:"remediation,omitempty"`
	Affected    []AffectedResource    `json:"affected,omitempty"`
}

// OpenShiftAuditSummary holds high-level counts for the OpenShift audit.
type OpenShiftAuditSummary struct {
	TotalFindings    int `json:"total_findings"`
	CriticalFindings int `json:"critical_findings"`
	HighFindings     int `json:"high_findings"`
	MediumFindings   int `json:"medium_findings"`
	LowFindings      int `json:"low_findings"`
}

// OpenShiftAuditResult is the output of RunOpenShiftAudit.
type OpenShiftAuditResult struct {
	IsOpenShift     bool                  `json:"is_openshift"`
	Summary         OpenShiftAuditSummary `json:"summary"`
	SCCAnalysis     *SCCAnalysisResult    `json:"scc_analysis,omitempty"`
	RouteFindings   []OpenShiftFinding    `json:"route_findings,omitempty"`
	OAuthFindings   []OpenShiftFinding    `json:"oauth_findings,omitempty"`
	BuildFindings   []OpenShiftFinding    `json:"build_findings,omitempty"`
	ProjectFindings []OpenShiftFinding    `json:"project_findings,omitempty"`
	RBACFindings    []OpenShiftFinding    `json:"rbac_findings,omitempty"`
}

// RunOpenShiftAudit performs an OpenShift-specific security audit on the graph.
// It detects whether this is an OpenShift cluster (via presence of SCC nodes)
// and then analyses Routes, OAuth clients, BuildConfigs, Projects, and SCCs.
func RunOpenShiftAudit(g *graph.Graph, opts OpenShiftAuditOptions) *OpenShiftAuditResult {
	result := &OpenShiftAuditResult{
		RouteFindings:   []OpenShiftFinding{},
		OAuthFindings:   []OpenShiftFinding{},
		BuildFindings:   []OpenShiftFinding{},
		ProjectFindings: []OpenShiftFinding{},
		RBACFindings:    []OpenShiftFinding{},
	}

	// Detect OpenShift by presence of SCC / Route / OAuthClient nodes.
	sccs := g.GetNodesByType(graph.NodeSCC)
	routes := g.GetNodesByType(graph.NodeRoute)
	oauthClients := g.GetNodesByType(graph.NodeOAuthClient)

	if len(sccs) == 0 && len(routes) == 0 && len(oauthClients) == 0 {
		result.IsOpenShift = false
		return result
	}
	result.IsOpenShift = true

	// Run SCC analysis using the existing AnalyzeSCCs function.
	result.SCCAnalysis = AnalyzeSCCs(g)

	// ---- Route analysis -----------------------------------------------------
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
		if !ri.TLSEnabled {
			result.RouteFindings = append(result.RouteFindings, OpenShiftFinding{
				CheckID:     "OCP_ROUTE001",
				Severity:    graph.SeverityHigh,
				Title:       "Route exposed without TLS",
				Description: "Route " + route.Namespace + "/" + route.Name + " is exposed without TLS termination",
				Remediation: "Configure TLS termination on the route",
				Affected: []AffectedResource{{
					Kind:      "Route",
					Namespace: route.Namespace,
					Name:      route.Name,
				}},
			})
		}
		if ri.InsecurePolicy == "Allow" {
			result.RouteFindings = append(result.RouteFindings, OpenShiftFinding{
				CheckID:     "OCP_ROUTE002",
				Severity:    graph.SeverityMedium,
				Title:       "Route allows insecure traffic",
				Description: "Route " + route.Namespace + "/" + route.Name + " allows insecure edge termination",
				Remediation: "Set insecureEdgeTerminationPolicy to None or Redirect",
				Affected: []AffectedResource{{
					Kind:      "Route",
					Namespace: route.Namespace,
					Name:      route.Name,
				}},
			})
		}
	}

	// ---- OAuth client analysis ----------------------------------------------
	for _, oauth := range oauthClients {
		if oauth.Metadata.OAuthClientInfo == nil {
			continue
		}
		oi := oauth.Metadata.OAuthClientInfo
		// Check for very long token lifetimes
		if oi.AccessTokenMaxAge > 0 && oi.AccessTokenMaxAge > 86400 {
			result.OAuthFindings = append(result.OAuthFindings, OpenShiftFinding{
				CheckID:     "OCP_OAUTH001",
				Severity:    graph.SeverityMedium,
				Title:       "OAuth client with long token lifetime",
				Description: "OAuth client " + oauth.Name + " has an access token lifetime > 24h",
				Remediation: "Reduce accessTokenMaxAgeSeconds to 1 hour or less",
				Affected: []AffectedResource{{
					Kind: "OAuthClient",
					Name: oauth.Name,
				}},
			})
		}
		// Check for redirect URIs with wildcards or http
		for _, uri := range oi.RedirectURIs {
			if strings.HasPrefix(uri, "http://") {
				result.OAuthFindings = append(result.OAuthFindings, OpenShiftFinding{
					CheckID:     "OCP_OAUTH002",
					Severity:    graph.SeverityHigh,
					Title:       "OAuth client with insecure redirect URI",
					Description: "OAuth client " + oauth.Name + " has a non-HTTPS redirect URI: " + uri,
					Remediation: "Use HTTPS redirect URIs only",
					Affected: []AffectedResource{{
						Kind: "OAuthClient",
						Name: oauth.Name,
					}},
				})
				break
			}
		}
	}

	// ---- BuildConfig analysis -----------------------------------------------
	buildConfigs := g.GetNodesByType(graph.NodeBuildConfig)
	for _, bc := range buildConfigs {
		if opts.Namespace != "" && bc.Namespace != opts.Namespace {
			continue
		}
		if !opts.IncludeSystem && isSystemNamespace(bc.Namespace) {
			continue
		}
		if bc.Metadata.BuildConfigInfo == nil {
			continue
		}
		bci := bc.Metadata.BuildConfigInfo
		if bci.Privileged {
			result.BuildFindings = append(result.BuildFindings, OpenShiftFinding{
				CheckID:     "OCP_BUILD001",
				Severity:    graph.SeverityCritical,
				Title:       "Privileged build configuration",
				Description: "BuildConfig " + bc.Namespace + "/" + bc.Name + " runs privileged containers",
				Remediation: "Avoid privileged builds; use unprivileged build strategies",
				Affected: []AffectedResource{{
					Kind:      "BuildConfig",
					Namespace: bc.Namespace,
					Name:      bc.Name,
				}},
			})
		}
		if bci.SourceType == "Dockerfile" {
			result.BuildFindings = append(result.BuildFindings, OpenShiftFinding{
				CheckID:     "OCP_BUILD002",
				Severity:    graph.SeverityMedium,
				Title:       "Dockerfile-based build strategy",
				Description: "BuildConfig " + bc.Namespace + "/" + bc.Name + " uses Dockerfile strategy (higher risk)",
				Remediation: "Consider using Source-to-Image (S2I) build strategy for better security",
				Affected: []AffectedResource{{
					Kind:      "BuildConfig",
					Namespace: bc.Namespace,
					Name:      bc.Name,
				}},
			})
		}
	}

	// ---- Project (namespace) analysis ---------------------------------------
	projects := g.GetNodesByType(graph.NodeProject)
	for _, proj := range projects {
		if opts.Namespace != "" && proj.Name != opts.Namespace {
			continue
		}
		if !opts.IncludeSystem && isSystemNamespace(proj.Name) {
			continue
		}
		if proj.Metadata.ProjectInfo == nil {
			continue
		}
		_ = proj.Metadata.ProjectInfo
		// Check for workloads in this project without network policies
		workloads := g.GetNodesByNamespace(proj.Name)
		projectHasNetPol := false
		for _, w := range workloads {
			if w.Type == graph.NodeWorkload && w.Metadata.NetworkPolicy != nil {
				projectHasNetPol = true
				break
			}
		}
		if !projectHasNetPol && len(workloads) > 0 {
			result.ProjectFindings = append(result.ProjectFindings, OpenShiftFinding{
				CheckID:     "OCP_PROJ001",
				Severity:    graph.SeverityMedium,
				Title:       "Project missing network policy",
				Description: "OpenShift project " + proj.Name + " has no NetworkPolicy - allows unrestricted traffic",
				Remediation: "Add a NetworkPolicy to restrict egress/ingress in this project",
				Affected: []AffectedResource{{
					Kind: "Project",
					Name: proj.Name,
				}},
			})
		}
	}

	// ---- OpenShift-specific RBAC --------------------------------------------
	// Dangerous SCC escalation paths are already captured in SCCAnalysis.
	// Here we add RBAC-level findings specific to OpenShift.
	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && isSystemNamespace(sa.Namespace) {
			continue
		}
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}
		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			for _, rule := range role.Metadata.Rules {
				// Check for access to OpenShift SCC escalation verbs
				for _, res := range rule.Resources {
					if res == "securitycontextconstraints" || res == "*" {
						for _, verb := range rule.Verbs {
							if verb == "use" || verb == "*" {
								result.RBACFindings = append(result.RBACFindings, OpenShiftFinding{
									CheckID:     "OCP_RBAC001",
									Severity:    graph.SeverityHigh,
									Title:       "ServiceAccount can use SCCs",
									Description: sa.Namespace + "/" + sa.Name + " can use SecurityContextConstraints via " + role.Name,
									Remediation: "Review SCC 'use' permissions; restrict to least-privilege SCCs",
									Affected: []AffectedResource{{
										Kind:      "ServiceAccount",
										Namespace: sa.Namespace,
										Name:      sa.Name,
									}},
								})
							}
						}
					}
				}
			}
		}
	}

	// Tally summary
	allFindings := make([]OpenShiftFinding, 0)
	allFindings = append(allFindings, result.RouteFindings...)
	allFindings = append(allFindings, result.OAuthFindings...)
	allFindings = append(allFindings, result.BuildFindings...)
	allFindings = append(allFindings, result.ProjectFindings...)
	allFindings = append(allFindings, result.RBACFindings...)

	result.Summary.TotalFindings = len(allFindings)
	for _, f := range allFindings {
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
