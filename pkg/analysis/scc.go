package analysis

import (
	"sort"
	"strings"

	"github.com/nelssec/identity-chain/pkg/graph"
)

type SCCAnalysisResult struct {
	SCCs            []SCCDetail
	SCCBindings     []SCCBinding
	RiskyBindings   []RiskySCCBinding
	EscalationPaths []SCCEscalationPath
	Summary         SCCSummary
}

type SCCDetail struct {
	Name          string
	Priority      int
	RiskLevel     string
	RiskScore     int
	Capabilities  []string
	Users         []string
	Groups        []string
	AllowedFlags  []string
	Restrictions  []string
}

type SCCBinding struct {
	SCCName         string
	SubjectType     string
	SubjectName     string
	SubjectNS       string
	EffectiveAccess []string
}

type RiskySCCBinding struct {
	SCCName       string
	SubjectType   string
	SubjectName   string
	SubjectNS     string
	RiskLevel     string
	RiskReason    string
	Capabilities  []string
}

type SCCEscalationPath struct {
	Source       string
	SourceType   string
	TargetSCC    string
	Via          string
	RiskLevel    string
	Description  string
}

type SCCSummary struct {
	TotalSCCs          int
	PrivilegedSCCs     int
	TotalBindings      int
	RiskyBindings      int
	EscalationPaths    int
	SAWithPrivileged   int
	UsersWithPrivileged int
}

func AnalyzeSCCs(g *graph.Graph) *SCCAnalysisResult {
	result := &SCCAnalysisResult{}

	sccs := g.GetNodesByType(graph.NodeSCC)
	if len(sccs) == 0 {
		return result
	}

	for _, scc := range sccs {
		detail := analyzeSCC(scc)
		result.SCCs = append(result.SCCs, detail)

		if detail.RiskLevel == "critical" || detail.RiskLevel == "high" {
			result.Summary.PrivilegedSCCs++
		}
	}

	sort.Slice(result.SCCs, func(i, j int) bool {
		return result.SCCs[i].RiskScore > result.SCCs[j].RiskScore
	})

	result.SCCBindings, result.RiskyBindings = analyzeSCCBindings(g, sccs)
	result.Summary.TotalBindings = len(result.SCCBindings)
	result.Summary.RiskyBindings = len(result.RiskyBindings)

	result.EscalationPaths = findSCCEscalationPaths(g, sccs)
	result.Summary.EscalationPaths = len(result.EscalationPaths)

	result.Summary.TotalSCCs = len(sccs)
	result.Summary.SAWithPrivileged = countSAsWithPrivilegedSCC(result.RiskyBindings)
	result.Summary.UsersWithPrivileged = countUsersWithPrivilegedSCC(result.RiskyBindings)

	return result
}

func analyzeSCC(scc *graph.Node) SCCDetail {
	info := scc.Metadata.SCCInfo
	if info == nil {
		return SCCDetail{Name: scc.Name}
	}

	detail := SCCDetail{
		Name:         scc.Name,
		Priority:     info.Priority,
		Users:        info.Users,
		Groups:       info.Groups,
		Capabilities: info.AllowedCapabilities,
	}

	riskScore := 0

	if info.AllowPrivilegedContainer {
		detail.AllowedFlags = append(detail.AllowedFlags, "privileged")
		riskScore += 100
	}
	if info.AllowHostNetwork {
		detail.AllowedFlags = append(detail.AllowedFlags, "hostNetwork")
		riskScore += 50
	}
	if info.AllowHostPID {
		detail.AllowedFlags = append(detail.AllowedFlags, "hostPID")
		riskScore += 50
	}
	if info.AllowHostIPC {
		detail.AllowedFlags = append(detail.AllowedFlags, "hostIPC")
		riskScore += 30
	}
	if info.AllowHostPorts {
		detail.AllowedFlags = append(detail.AllowedFlags, "hostPorts")
		riskScore += 20
	}
	if info.AllowHostDirVolumePlugin {
		detail.AllowedFlags = append(detail.AllowedFlags, "hostPath")
		riskScore += 60
	}

	for _, cap := range info.AllowedCapabilities {
		if cap == "*" || cap == "ALL" {
			riskScore += 80
		} else if isDangerousCapability(cap) {
			riskScore += 30
		}
	}

	if info.RunAsUserType == "RunAsAny" {
		detail.AllowedFlags = append(detail.AllowedFlags, "runAsAny")
		riskScore += 40
	}

	if info.AllowPrivilegeEscalation == nil || *info.AllowPrivilegeEscalation {
		detail.AllowedFlags = append(detail.AllowedFlags, "allowPrivilegeEscalation")
		riskScore += 20
	}

	if info.RunAsUserType == "MustRunAsNonRoot" {
		detail.Restrictions = append(detail.Restrictions, "mustRunAsNonRoot")
	}
	if info.ReadOnlyRootFilesystem {
		detail.Restrictions = append(detail.Restrictions, "readOnlyRootFS")
	}
	if len(info.RequiredDropCapabilities) > 0 {
		detail.Restrictions = append(detail.Restrictions, "dropCapabilities")
	}

	detail.RiskScore = riskScore
	detail.RiskLevel = scoreToRiskLevel(riskScore)

	return detail
}

func isDangerousCapability(cap string) bool {
	dangerous := map[string]bool{
		"SYS_ADMIN":     true,
		"SYS_PTRACE":    true,
		"SYS_MODULE":    true,
		"SYS_RAWIO":     true,
		"DAC_OVERRIDE":  true,
		"NET_ADMIN":     true,
		"NET_RAW":       true,
		"SETUID":        true,
		"SETGID":        true,
		"CHOWN":         true,
		"CAP_SYS_ADMIN": true,
	}
	return dangerous[strings.ToUpper(cap)]
}

func scoreToRiskLevel(score int) string {
	switch {
	case score >= 100:
		return "critical"
	case score >= 60:
		return "high"
	case score >= 30:
		return "medium"
	default:
		return "low"
	}
}

func analyzeSCCBindings(g *graph.Graph, sccs []*graph.Node) ([]SCCBinding, []RiskySCCBinding) {
	var bindings []SCCBinding
	var riskyBindings []RiskySCCBinding

	sccMap := make(map[string]*graph.Node)
	for _, scc := range sccs {
		sccMap[scc.Name] = scc
	}

	for _, scc := range sccs {
		info := scc.Metadata.SCCInfo
		if info == nil {
			continue
		}

		sccDetail := analyzeSCC(scc)

		for _, user := range info.Users {
			binding := SCCBinding{
				SCCName:         scc.Name,
				SubjectType:     "User",
				SubjectName:     user,
				EffectiveAccess: sccDetail.AllowedFlags,
			}

			if strings.HasPrefix(user, "system:serviceaccount:") {
				parts := strings.Split(user, ":")
				if len(parts) >= 4 {
					binding.SubjectType = "ServiceAccount"
					binding.SubjectNS = parts[2]
					binding.SubjectName = parts[3]
				}
			}

			bindings = append(bindings, binding)

			if sccDetail.RiskLevel == "critical" || sccDetail.RiskLevel == "high" {
				risky := RiskySCCBinding{
					SCCName:      scc.Name,
					SubjectType:  binding.SubjectType,
					SubjectName:  binding.SubjectName,
					SubjectNS:    binding.SubjectNS,
					RiskLevel:    sccDetail.RiskLevel,
					RiskReason:   strings.Join(sccDetail.AllowedFlags, ", "),
					Capabilities: sccDetail.Capabilities,
				}
				riskyBindings = append(riskyBindings, risky)
			}
		}

		for _, group := range info.Groups {
			binding := SCCBinding{
				SCCName:         scc.Name,
				SubjectType:     "Group",
				SubjectName:     group,
				EffectiveAccess: sccDetail.AllowedFlags,
			}
			bindings = append(bindings, binding)

			if group == "system:authenticated" || group == "system:serviceaccounts" {
				if sccDetail.RiskLevel == "critical" || sccDetail.RiskLevel == "high" {
					risky := RiskySCCBinding{
						SCCName:      scc.Name,
						SubjectType:  "Group",
						SubjectName:  group,
						RiskLevel:    "critical",
						RiskReason:   "Broad group (" + group + ") has access to privileged SCC",
						Capabilities: sccDetail.Capabilities,
					}
					riskyBindings = append(riskyBindings, risky)
				}
			}
		}
	}

	return bindings, riskyBindings
}

func findSCCEscalationPaths(g *graph.Graph, sccs []*graph.Node) []SCCEscalationPath {
	var paths []SCCEscalationPath

	sccMap := make(map[string]*graph.Node)
	privilegedSCCs := make(map[string]bool)
	for _, scc := range sccs {
		sccMap[scc.Name] = scc
		detail := analyzeSCC(scc)
		if detail.RiskLevel == "critical" || detail.RiskLevel == "high" {
			privilegedSCCs[scc.Name] = true
		}
	}

	roles := g.GetNodesByType(graph.NodeRole)
	for _, role := range roles {
		canUseSCC := false
		var sccNames []string

		for _, rule := range role.Metadata.Rules {
			for _, resource := range rule.Resources {
				if resource == "securitycontextconstraints" || resource == "*" {
					for _, verb := range rule.Verbs {
						if verb == "use" || verb == "*" {
							canUseSCC = true
							if len(rule.ResourceNames) > 0 {
								sccNames = rule.ResourceNames
							}
						}
					}
				}
			}
		}

		if !canUseSCC {
			continue
		}

		bindings := g.GetInEdges(role.ID)
		for _, edge := range bindings {
			if edge.Type != graph.EdgeBinds {
				continue
			}

			subject := g.GetNode(edge.From)
			if subject == nil {
				continue
			}

			for sccName := range privilegedSCCs {
				if len(sccNames) > 0 {
					found := false
					for _, name := range sccNames {
						if name == sccName {
							found = true
							break
						}
					}
					if !found {
						continue
					}
				}

				path := SCCEscalationPath{
					Source:      subject.Name,
					SourceType:  string(subject.Type),
					TargetSCC:   sccName,
					Via:         role.Name,
					RiskLevel:   "high",
					Description: subject.Name + " can use " + sccName + " via " + role.Name,
				}

				if subject.Type == graph.NodeServiceAccount {
					workloads := g.GetInEdges(subject.ID)
					for _, wEdge := range workloads {
						if wEdge.Type == graph.EdgeUses {
							path.RiskLevel = "critical"
							path.Description += " (used by workloads)"
							break
						}
					}
				}

				paths = append(paths, path)
			}
		}
	}

	return paths
}

func countSAsWithPrivilegedSCC(bindings []RiskySCCBinding) int {
	saSet := make(map[string]bool)
	for _, b := range bindings {
		if b.SubjectType == "ServiceAccount" {
			key := b.SubjectNS + "/" + b.SubjectName
			saSet[key] = true
		}
	}
	return len(saSet)
}

func countUsersWithPrivilegedSCC(bindings []RiskySCCBinding) int {
	userSet := make(map[string]bool)
	for _, b := range bindings {
		if b.SubjectType == "User" {
			userSet[b.SubjectName] = true
		}
	}
	return len(userSet)
}

func (r *SCCAnalysisResult) GetSCCByName(name string) *SCCDetail {
	for _, scc := range r.SCCs {
		if scc.Name == name {
			return &scc
		}
	}
	return nil
}

func (r *SCCAnalysisResult) GetBindingsForSubject(subjectType, name, namespace string) []SCCBinding {
	var result []SCCBinding
	for _, b := range r.SCCBindings {
		if b.SubjectType == subjectType && b.SubjectName == name {
			if namespace == "" || b.SubjectNS == namespace {
				result = append(result, b)
			}
		}
	}
	return result
}
