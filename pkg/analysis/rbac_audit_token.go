package analysis

import (
	"github.com/nelssec/identity-chain/pkg/collector"
	"github.com/nelssec/identity-chain/pkg/graph"
)

func checkTokenCreate(g *graph.Graph, opts RBACAuditOptions) []RBACFinding {
	var findings []RBACFinding
	var affected []AffectedResource

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	for _, sa := range serviceAccounts {
		if !opts.IncludeSystem && collector.IsSystemNamespace(sa.Namespace) {
			continue
		}
		if opts.Namespace != "" && sa.Namespace != opts.Namespace {
			continue
		}

		roles := collectBoundRoles(g, sa.ID)
		for _, role := range roles {
			edges := g.GetOutEdges(role.ID)
			for _, e := range edges {
				if e.Type != graph.EdgeGrants {
					continue
				}
				resourceNode := g.GetNode(e.To)
				if resourceNode == nil {
					continue
				}

				kind := resourceNode.Metadata.ResourceKind
				if kind == "serviceaccounts/token" || kind == "*" {
					if containsString(e.Metadata.Verbs, "create") || containsString(e.Metadata.Verbs, "*") {
						affected = append(affected, AffectedResource{
							Kind:      "ServiceAccount",
							Namespace: sa.Namespace,
							Name:      sa.Name,
							Details:   "Can create tokens for service accounts via " + role.Name,
						})
						break
					}
				}
			}
		}
	}

	if len(affected) > 0 {
		findings = append(findings, RBACFinding{
			Severity:    graph.SeverityHigh,
			Title:       "ServiceAccounts that can create SA tokens",
			Description: "The serviceaccounts/token create permission allows generating tokens for any service account, enabling identity impersonation via the TokenRequest API",
			Affected:    affected,
			Remediation: "Remove serviceaccounts/token create permission or restrict to specific service accounts using resourceNames",
			References:  []string{"https://kubernetes.io/docs/reference/kubernetes-api/authentication-resources/token-request-v1/"},
		})
	}

	return findings
}
