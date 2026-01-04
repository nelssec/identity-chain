package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/audit"
	"github.com/nelssec/identity-chain/pkg/collector"
	"github.com/nelssec/identity-chain/pkg/collector/cloud"
	"github.com/nelssec/identity-chain/pkg/graph"
	"github.com/nelssec/identity-chain/pkg/output"
	"github.com/spf13/cobra"
)

var (
	namespace     string
	allNamespaces bool
	kubeconfig    string
	kubecontext   string
	outputFormat  string
	includeSystem bool
	includeCloud  bool
	awsRegion     string
	gcpProject    string
	azureSubID    string
)

// resolveWorkloadNodeID finds the node ID for a workload reference
func resolveWorkloadNodeID(g *graph.Graph, workloadRef, ns string) string {
	kind, ns, name := graph.ParseWorkloadRef(workloadRef, ns)
	nodeID := graph.GenerateNodeID(graph.NodeWorkload, ns, name)

	node := g.GetNode(nodeID)
	if node == nil {
		nodes := g.GetNodesByNamespace(ns)
		for _, n := range nodes {
			if n.Type == graph.NodeWorkload && n.Name == name {
				if kind == "" || n.Metadata.WorkloadKind == kind {
					return n.ID
				}
			}
		}
	}
	return nodeID
}

func main() {
	rootCmd := &cobra.Command{
		Use:   "idc",
		Short: "Identity Chain - Kubernetes identity and blast radius analyzer",
		Long: `Identity Chain analyzes Kubernetes RBAC and cloud IAM to map
identity chains and calculate blast radius for workloads.

Examples:
  idc blast --workload deployment/api-server -n prod
  idc blast --all -A
  idc graph -o dot > cluster.dot`,
	}

	rootCmd.PersistentFlags().StringVarP(&namespace, "namespace", "n", "default", "Kubernetes namespace")
	rootCmd.PersistentFlags().BoolVarP(&allNamespaces, "all-namespaces", "A", false, "Scan all namespaces")
	rootCmd.PersistentFlags().StringVar(&kubeconfig, "kubeconfig", "", "Path to kubeconfig file")
	rootCmd.PersistentFlags().StringVar(&kubecontext, "context", "", "Kubernetes context to use")
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, dot")
	rootCmd.PersistentFlags().BoolVar(&includeSystem, "include-system", false, "Include system namespaces")
	rootCmd.PersistentFlags().BoolVar(&includeCloud, "include-cloud", false, "Include cloud IAM analysis (AWS/GCP/Azure)")
	rootCmd.PersistentFlags().StringVar(&awsRegion, "aws-region", "", "AWS region for IAM lookups")
	rootCmd.PersistentFlags().StringVar(&gcpProject, "gcp-project", "", "GCP project for IAM lookups")
	rootCmd.PersistentFlags().StringVar(&azureSubID, "azure-subscription", "", "Azure subscription ID")

	rootCmd.AddCommand(blastCmd())
	rootCmd.AddCommand(graphCmd())
	rootCmd.AddCommand(scanCmd())
	rootCmd.AddCommand(unusedCmd())
	rootCmd.AddCommand(auditCmd())
	rootCmd.AddCommand(identityCmd())
	rootCmd.AddCommand(privescCmd())
	rootCmd.AddCommand(whocanCmd())
	rootCmd.AddCommand(whatcanCmd())
	rootCmd.AddCommand(rbacAuditCmd())
	rootCmd.AddCommand(cloudAuditCmd())
	rootCmd.AddCommand(podSecurityCmd())
	rootCmd.AddCommand(networkPolicyCmd())
	rootCmd.AddCommand(attackPathCmd())
	rootCmd.AddCommand(dashboardCmd())

	if err := rootCmd.Execute(); err != nil {
		os.Exit(1)
	}
}

func blastCmd() *cobra.Command {
	var workload string
	var all bool

	cmd := &cobra.Command{
		Use:   "blast",
		Short: "Calculate blast radius for a workload",
		Long: `Analyze the blast radius of a workload by tracing its identity chain
from the workload through ServiceAccount, RBAC bindings, and cloud roles.

Examples:
  idc blast --workload deployment/api-server -n prod
  idc blast --workload sts/postgres -n database
  idc blast --all -A -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))

			if all {
				results, err := analysis.AllWorkloadBlastRadius(g)
				if err != nil {
					return fmt.Errorf("blast radius analysis failed: %w", err)
				}
				return writer.WriteBlastResults(results)
			}

			if workload == "" {
				return fmt.Errorf("--workload or --all is required")
			}

			nodeID := resolveWorkloadNodeID(g, workload, namespace)
			result, err := analysis.BlastRadius(g, nodeID)
			if err != nil {
				return fmt.Errorf("blast radius analysis failed: %w", err)
			}

			if result == nil {
				return fmt.Errorf("workload not found: %s", workload)
			}

			return writer.WriteBlastResult(result)
		},
	}

	cmd.Flags().StringVarP(&workload, "workload", "w", "", "Workload to analyze (e.g., deployment/api-server)")
	cmd.Flags().BoolVar(&all, "all", false, "Analyze all workloads")

	return cmd
}

func graphCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "graph",
		Short: "Export the full identity graph",
		Long: `Export the complete identity chain graph in various formats.
Use DOT format to generate visualizations with Graphviz.

Examples:
  idc graph -o dot > cluster.dot
  idc graph -o dot | dot -Tpng > cluster.png
  idc graph -o json > cluster.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
			return writer.WriteGraph(g)
		},
	}

	return cmd
}

func scanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan cluster and show statistics",
		Long: `Scan the cluster and display identity chain statistics.

Examples:
  idc scan -A
  idc scan -n prod -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
			return writer.WriteStats(g.Stats())
		},
	}

	return cmd
}

func collectGraph(ctx context.Context) (*graph.Graph, error) {
	opts := collector.Options{
		Namespace:      namespace,
		AllNamespaces:  allNamespaces,
		IncludeSystem:  includeSystem,
		KubeConfigPath: kubeconfig,
		KubeContext:    kubecontext,
	}

	k8sCollector, err := collector.NewKubernetesCollector(opts)
	if err != nil {
		return nil, err
	}

	builder := graph.NewBuilder()
	if err := k8sCollector.Collect(ctx, builder); err != nil {
		return nil, err
	}

	if includeCloud {
		cloudCollector := cloud.NewMultiCloudCollector()

		if awsRegion != "" {
			awsCollector, err := cloud.NewAWSCollector(ctx, awsRegion)
			if err == nil {
				cloudCollector.Register(awsCollector)
			}
		}

		for _, sa := range builder.GetServiceAccountsWithCloudIdentity() {
			_ = cloudCollector.CollectForServiceAccount(ctx, builder, sa)
		}
	}

	return builder.Build(), nil
}

func unusedCmd() *cobra.Command {
	var since string
	var auditSource string
	var auditPath string
	var esEndpoint string
	var esIndex string

	cmd := &cobra.Command{
		Use:   "unused",
		Short: "Find unused RBAC permissions",
		Long: `Analyze audit logs to find permissions granted but never used.
This helps identify overprivileged service accounts.

Examples:
  idc unused --since 30d --audit-source file --audit-path /var/log/audit/
  idc unused --since 7d --audit-source elasticsearch --es-endpoint http://es:9200`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			var source audit.Source
			switch auditSource {
			case "file":
				source = audit.NewDirectorySource(auditPath, "*.log")
			case "elasticsearch":
				source = audit.NewElasticsearchSource(esEndpoint, esIndex, "", "")
			default:
				return fmt.Errorf("unsupported audit source: %s", auditSource)
			}
			defer source.Close()

			duration, err := parseDuration(since)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}

			analyzer := audit.NewAnalyzer(source, g)
			queryOpts := audit.QueryOptions{
				StartTime:     time.Now().Add(-duration),
				EndTime:       time.Now(),
				IncludeSystem: includeSystem,
			}
			if namespace != "default" {
				queryOpts.Namespace = namespace
			}

			if err := analyzer.Analyze(ctx, queryOpts); err != nil {
				return fmt.Errorf("audit analysis failed: %w", err)
			}

			unused := analyzer.GetUnusedPermissions(duration)

			fmt.Fprintf(os.Stdout, "=== Unused Permissions (last %s) ===\n\n", since)
			fmt.Fprintf(os.Stdout, "%-40s %-20s %-15s %-10s %s\n", "SERVICE ACCOUNT", "RESOURCE", "VERB", "STATUS", "VIA ROLE")
			fmt.Fprintf(os.Stdout, "%s\n", "─────────────────────────────────────────────────────────────────────────────────────────────────────────────────")

			for _, u := range unused {
				status := "UNUSED"
				if u.NeverUsed {
					status = "NEVER"
				} else {
					status = fmt.Sprintf("%dd ago", u.DaysSinceUse)
				}
				fmt.Fprintf(os.Stdout, "%-40s %-20s %-15s %-10s %s\n",
					truncate(u.ServiceAccount, 40),
					u.Resource,
					u.Verb,
					status,
					u.ViaRole)
			}

			fmt.Fprintf(os.Stdout, "\nTotal: %d unused permissions\n", len(unused))
			return nil
		},
	}

	cmd.Flags().StringVar(&since, "since", "30d", "Time period to analyze (e.g., 7d, 30d)")
	cmd.Flags().StringVar(&auditSource, "audit-source", "file", "Audit log source: file, elasticsearch, loki")
	cmd.Flags().StringVar(&auditPath, "audit-path", "/var/log/kubernetes/audit/", "Path to audit log files")
	cmd.Flags().StringVar(&esEndpoint, "es-endpoint", "", "Elasticsearch endpoint URL")
	cmd.Flags().StringVar(&esIndex, "es-index", "kubernetes-audit-*", "Elasticsearch index pattern")

	return cmd
}

func auditCmd() *cobra.Command {
	var auditSource string
	var auditPath string
	var esEndpoint string
	var esIndex string
	var since string
	var realtime bool

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Analyze Kubernetes audit logs",
		Long: `Parse and analyze Kubernetes audit logs to track permission usage.

Examples:
  idc audit --since 24h --audit-source file --audit-path /var/log/audit/
  idc audit --realtime --audit-source elasticsearch`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			var source audit.Source
			switch auditSource {
			case "file":
				source = audit.NewDirectorySource(auditPath, "*.log")
			case "elasticsearch":
				source = audit.NewElasticsearchSource(esEndpoint, esIndex, "", "")
			case "loki":
				source = audit.NewLokiSource(esEndpoint, "")
			default:
				return fmt.Errorf("unsupported audit source: %s", auditSource)
			}
			defer source.Close()

			if realtime {
				return runRealtimeMonitor(ctx, source)
			}

			duration, err := parseDuration(since)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}

			queryOpts := audit.QueryOptions{
				StartTime:     time.Now().Add(-duration),
				EndTime:       time.Now(),
				IncludeSystem: includeSystem,
				Limit:         10000,
			}
			if namespace != "default" {
				queryOpts.Namespace = namespace
			}

			tracker := audit.NewUsageTracker()
			events, err := source.GetEvents(ctx, queryOpts)
			if err != nil {
				return fmt.Errorf("failed to get audit events: %w", err)
			}

			for _, event := range events {
				tracker.Track(event)
			}

			summary := tracker.Summarize()

			fmt.Fprintf(os.Stdout, "=== Audit Log Summary ===\n\n")
			fmt.Fprintf(os.Stdout, "Time Range: %s to %s\n",
				summary.TimeRange.Start.Format(time.RFC3339),
				summary.TimeRange.End.Format(time.RFC3339))
			fmt.Fprintf(os.Stdout, "Total Events: %d\n", summary.TotalEvents)
			fmt.Fprintf(os.Stdout, "Unique Users: %d\n", summary.UniqueUsers)
			fmt.Fprintf(os.Stdout, "Unique Resources: %d\n", summary.UniqueResources)
			fmt.Fprintf(os.Stdout, "Failure Rate: %.2f%%\n\n", summary.FailureRate*100)

			fmt.Fprintf(os.Stdout, "=== Verb Distribution ===\n")
			for verb, count := range summary.VerbDistribution {
				fmt.Fprintf(os.Stdout, "  %-15s %d\n", verb, count)
			}

			fmt.Fprintf(os.Stdout, "\n=== Top Service Accounts ===\n")
			limit := 10
			if len(summary.TopUsers) < limit {
				limit = len(summary.TopUsers)
			}
			for i := 0; i < limit; i++ {
				u := summary.TopUsers[i]
				fmt.Fprintf(os.Stdout, "  %-50s %d\n", truncate(u.User, 50), u.Count)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&since, "since", "24h", "Time period to analyze")
	cmd.Flags().StringVar(&auditSource, "audit-source", "file", "Audit log source: file, elasticsearch, loki")
	cmd.Flags().StringVar(&auditPath, "audit-path", "/var/log/kubernetes/audit/", "Path to audit log files")
	cmd.Flags().StringVar(&esEndpoint, "es-endpoint", "", "Elasticsearch/Loki endpoint URL")
	cmd.Flags().StringVar(&esIndex, "es-index", "kubernetes-audit-*", "Elasticsearch index pattern")
	cmd.Flags().BoolVar(&realtime, "realtime", false, "Enable realtime monitoring mode")

	return cmd
}

func runRealtimeMonitor(ctx context.Context, source audit.Source) error {
	monitor := audit.NewRealTimeMonitor(source)

	monitor.AddAlertRule(audit.SecretsAccessRule(func(e audit.Event) {
		fmt.Fprintf(os.Stderr, "[ALERT] Secrets access: %s accessed %s/%s\n",
			e.User.Username, e.ObjectRef.Namespace, e.ObjectRef.Name)
	}))

	monitor.AddAlertRule(audit.PrivilegeEscalationRule(func(e audit.Event) {
		fmt.Fprintf(os.Stderr, "[ALERT] Potential privesc: %s %s %s/%s\n",
			e.User.Username, e.Verb, e.ObjectRef.Resource, e.ObjectRef.Name)
	}))

	monitor.AddAlertRule(audit.UnauthorizedAccessRule(func(e audit.Event) {
		fmt.Fprintf(os.Stderr, "[WARN] Unauthorized: %s tried to %s %s/%s\n",
			e.User.Username, e.Verb, e.ObjectRef.Resource, e.ObjectRef.Name)
	}))

	fmt.Println("Starting realtime audit monitoring (Ctrl+C to stop)...")
	return monitor.Start(ctx, audit.QueryOptions{
		StartTime:     time.Now(),
		IncludeSystem: includeSystem,
	})
}

func parseDuration(s string) (time.Duration, error) {
	if len(s) == 0 {
		return 0, fmt.Errorf("empty duration")
	}

	unit := s[len(s)-1]
	value := s[:len(s)-1]

	var multiplier time.Duration
	switch unit {
	case 'h':
		multiplier = time.Hour
	case 'd':
		multiplier = 24 * time.Hour
	case 'w':
		multiplier = 7 * 24 * time.Hour
	default:
		return time.ParseDuration(s)
	}

	var num int
	for _, c := range value {
		if c < '0' || c > '9' {
			return time.ParseDuration(s)
		}
		num = num*10 + int(c-'0')
	}

	return time.Duration(num) * multiplier, nil
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max-3] + "..."
}

func identityCmd() *cobra.Command {
	var azureWorkspaceID string

	cmd := &cobra.Command{
		Use:   "identity",
		Short: "Analyze cloud identity bindings for service accounts",
		Long: `Show Kubernetes service accounts with cloud identity bindings.
This traces K8s SAs to Azure Managed Identity, AWS IRSA, or GCP Workload Identity.

Examples:
  idc identity -A --azure-subscription <sub-id>
  idc identity -A --aws-region us-west-2
  idc identity -n prod -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			opts := collector.Options{
				Namespace:      namespace,
				AllNamespaces:  allNamespaces,
				IncludeSystem:  includeSystem,
				KubeConfigPath: kubeconfig,
				KubeContext:    kubecontext,
			}

			k8sCollector, err := collector.NewKubernetesCollector(opts)
			if err != nil {
				return err
			}

			builder := graph.NewBuilder()
			if err := k8sCollector.Collect(ctx, builder); err != nil {
				return err
			}

			g := builder.Build()
			cloudSAs := builder.GetServiceAccountsWithCloudIdentity()
			if len(cloudSAs) == 0 {
				fmt.Println("No service accounts with cloud identity bindings found.")
				fmt.Println("\nTo enable cloud identity:")
				fmt.Println("  Azure: Add annotation azure.workload.identity/client-id to ServiceAccount")
				fmt.Println("  AWS:   Add annotation eks.amazonaws.com/role-arn to ServiceAccount")
				fmt.Println("  GCP:   Add annotation iam.gke.io/gcp-service-account to ServiceAccount")
				return nil
			}

			fmt.Printf("=== Cloud Identity Bindings (%d service accounts) ===\n\n", len(cloudSAs))

			var azureCollector *cloud.AzureCollector
			if azureSubID != "" {
				azureCollector, _ = cloud.NewAzureCollector(ctx, azureSubID)
			}

			var awsCollector *cloud.AWSCollector
			if awsRegion != "" {
				awsCollector, _ = cloud.NewAWSCollector(ctx, awsRegion)
			}

			for _, sa := range cloudSAs {
				fmt.Printf("------------------------------------------------------------------------------\n")
				fmt.Printf("ServiceAccount: %s/%s\n", sa.Namespace, sa.Name)

				if sa.Metadata.CloudRoleARN != "" {
					provider := detectCloudProvider(sa.Metadata.CloudRoleARN)
					fmt.Printf("   Cloud: %s\n", provider)
					fmt.Printf("   Identity: %s\n", sa.Metadata.CloudRoleARN)

					switch provider {
					case "Azure":
						if azureCollector != nil {
							info, err := azureCollector.AnalyzeWorkloadIdentity(ctx, sa.Metadata.CloudRoleARN)
							if err == nil && len(info.RoleAssignments) > 0 {
								fmt.Printf("\n   Azure Role Assignments:\n")
								for _, ra := range info.RoleAssignments {
									fmt.Printf("   -  Role: %s\n", ra.RoleName)
									fmt.Printf("     Scope: %s\n", truncateScope(ra.Scope))
									if len(ra.Actions) > 0 {
										fmt.Printf("     Actions: %v\n", truncateActions(ra.Actions, 3))
									}
									if len(ra.DataActions) > 0 {
										fmt.Printf("     DataActions: %v\n", truncateActions(ra.DataActions, 3))
									}
								}
							} else if err != nil {
								fmt.Printf("   Warning: Could not fetch Azure roles: %v\n", err)
							}
						} else {
							fmt.Printf("   Note: Use --azure-subscription to fetch role details\n")
						}

					case "AWS":
						if awsCollector != nil {
							roleInfo, err := awsCollector.CollectRole(ctx, sa.Metadata.CloudRoleARN)
							if err == nil && len(roleInfo.Policies) > 0 {
								fmt.Printf("\n   AWS IAM Policies:\n")
								for _, policy := range roleInfo.Policies {
									fmt.Printf("   -  Policy: %s\n", policy.Name)
									if policy.IsAdmin {
										fmt.Printf("     Warning: ADMIN POLICY\n")
									}
									for _, stmt := range policy.Statements {
										if len(stmt.Action) > 0 {
											fmt.Printf("     Actions: %v\n", truncateActions(stmt.Action, 3))
										}
									}
								}
							} else if err != nil {
								fmt.Printf("   Warning: Could not fetch AWS roles: %v\n", err)
							}
						} else {
							fmt.Printf("   Note: Use --aws-region to fetch role details\n")
						}
					}
				}

				workloads := g.GetWorkloadsUsingSA(sa.ID)
				if len(workloads) > 0 {
					fmt.Printf("\n   Used by workloads:\n")
					for _, w := range workloads {
						fmt.Printf("   -  %s/%s (%s)\n", w.Namespace, w.Name, w.Metadata.WorkloadKind)
					}
				} else {
					fmt.Printf("\n   Warning: UNUSED - No workloads using this SA\n")
				}

				fmt.Println()
			}

			if azureWorkspaceID != "" {
				fmt.Println("\n=== Azure Audit Log Usage ===")
				fmt.Println("Querying Azure Log Analytics for recent activity...")

				source, err := audit.NewAzureLogAnalyticsSource(azureWorkspaceID)
				if err != nil {
					fmt.Printf("Warning: Could not connect to Log Analytics: %v\n", err)
				} else {
					opts := audit.QueryOptions{
						StartTime: time.Now().Add(-24 * time.Hour),
						EndTime:   time.Now(),
					}
					events, err := source.GetEvents(ctx, opts)
					if err != nil {
						fmt.Printf("Warning: Query failed: %v\n", err)
					} else {
						fmt.Printf("Found %d audit events in last 24h\n", len(events))
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&azureWorkspaceID, "azure-workspace", "", "Azure Log Analytics workspace ID for usage data")

	return cmd
}

func detectCloudProvider(identity string) string {
	// Azure client ID is a UUID format
	if len(identity) == 36 && identity[8] == '-' && identity[13] == '-' {
		return "Azure"
	}
	// AWS ARN format
	if strings.HasPrefix(identity, "arn:") {
		return "AWS"
	}
	// GCP service account email format
	if strings.HasSuffix(identity, ".iam.gserviceaccount.com") {
		return "GCP"
	}
	return "Unknown"
}

func truncateScope(scope string) string {
	if len(scope) > 80 {
		parts := strings.Split(scope, "/")
		if len(parts) > 3 {
			parts = append(parts[:3], "...")
		}
		return strings.Join(parts, "/")
	}
	return scope
}

func truncateActions(actions []string, max int) []string {
	if len(actions) <= max {
		return actions
	}
	result := actions[:max]
	result = append(result, fmt.Sprintf("+%d more", len(actions)-max))
	return result
}

func privescCmd() *cobra.Command {
	var workload string
	var all bool
	var maxDepth int

	cmd := &cobra.Command{
		Use:   "privesc",
		Short: "Find privilege escalation paths",
		Long: `Detect potential privilege escalation paths in RBAC configuration.
Identifies dangerous permissions like bind, escalate, impersonate, and pod creation
that could allow an attacker to elevate privileges.

Examples:
  idc privesc --all -A
  idc privesc --workload deployment/api-server -n prod
  idc privesc --all -A --depth 5`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			if all {
				results, err := analysis.FindAllPrivescPaths(g, maxDepth)
				if err != nil {
					return fmt.Errorf("privesc analysis failed: %w", err)
				}

				writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
				return writer.WritePrivescResults(results)
			}

			if workload == "" {
				return fmt.Errorf("--workload or --all is required")
			}

			nodeID := resolveWorkloadNodeID(g, workload, namespace)
			result, err := analysis.FindPrivescPaths(g, nodeID, maxDepth)
			if err != nil {
				return fmt.Errorf("privesc analysis failed: %w", err)
			}

			if result == nil {
				return fmt.Errorf("workload not found: %s", workload)
			}

			if len(result.DirectVectors) == 0 && len(result.Paths) == 0 {
				fmt.Println("No privilege escalation paths found for this workload.")
				return nil
			}

			fmt.Printf("=== Privilege Escalation Analysis for %s ===\n\n", workload)
			fmt.Printf("Max Severity: %s\n", result.MaxSeverity)
			fmt.Printf("Can reach cluster-admin: %v\n", result.CanReachAdmin)

			if len(result.DirectVectors) > 0 {
				fmt.Printf("\nDirect Vectors:\n")
				for _, v := range result.DirectVectors {
					fmt.Printf("  [%s] %s\n", v.Severity, v.Vector.String())
					fmt.Printf("    %s\n", v.Description)
					fmt.Printf("    Via: %s\n", v.Role.Name)
				}
			}

			if len(result.Paths) > 0 {
				fmt.Printf("\nMulti-hop Paths:\n")
				for i, p := range result.Paths {
					fmt.Printf("  Path %d [%s]: %s\n", i+1, p.Severity, p.Description)
					for _, step := range p.Steps {
						fmt.Printf("    Step %d: %s\n", step.StepNumber, step.Description)
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&workload, "workload", "w", "", "Workload to analyze")
	cmd.Flags().BoolVar(&all, "all", false, "Analyze all workloads")
	cmd.Flags().IntVar(&maxDepth, "depth", 3, "Maximum path depth to search")

	return cmd
}

func whocanCmd() *cobra.Command {
	var resourceName string

	cmd := &cobra.Command{
		Use:   "whocan [verb] [resource]",
		Short: "Find who can perform an action",
		Long: `Reverse RBAC lookup - find all subjects that can perform a given action.

Examples:
  idc whocan get secrets -n prod
  idc whocan create pods -A
  idc whocan delete deployments -n prod
  idc whocan create clusterrolebindings`,
		Args: cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			verb := args[0]
			resource := args[1]

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			query := analysis.WhoCanQuery{
				Verb:         verb,
				Resource:     resource,
				ResourceName: resourceName,
				Namespace:    namespace,
			}

			if allNamespaces {
				query.Namespace = ""
			}

			result, err := analysis.WhoCan(g, query)
			if err != nil {
				return fmt.Errorf("whocan query failed: %w", err)
			}

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
			return writer.WriteWhoCanResult(result)
		},
	}

	cmd.Flags().StringVar(&resourceName, "resource-name", "", "Specific resource name to check")

	return cmd
}

func whatcanCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "whatcan [serviceaccount]",
		Short: "Show all permissions for a service account",
		Long: `List all permissions granted to a specific service account.

Examples:
  idc whatcan my-service-account -n prod
  idc whatcan default -n kube-system`,
		Args: cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			saName := args[0]

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			query := analysis.ReverseRBACQuery{
				SubjectKind: "ServiceAccount",
				SubjectName: saName,
				Namespace:   namespace,
			}

			result, err := analysis.WhatCan(g, query)
			if err != nil {
				return fmt.Errorf("whatcan query failed: %w", err)
			}

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
			return writer.WriteWhatCanResult(result)
		},
	}

	return cmd
}

func rbacAuditCmd() *cobra.Command {
	var checks string
	var skipChecks string

	cmd := &cobra.Command{
		Use:   "rbac-audit",
		Short: "Run RBAC security audit",
		Long: `Comprehensive security audit of RBAC configuration.
Checks for dangerous permissions, over-privileged accounts, and misconfigurations.

Examples:
  idc rbac-audit -A
  idc rbac-audit -n prod
  idc rbac-audit -A --checks RBAC001,RBAC002
  idc rbac-audit -A --skip RBAC010`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.RBACAuditOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}

			if allNamespaces {
				opts.Namespace = ""
			}

			if checks != "" {
				opts.ChecksToRun = strings.Split(checks, ",")
			}
			if skipChecks != "" {
				opts.SkipChecks = strings.Split(skipChecks, ",")
			}

			result := analysis.RunRBACAudit(g, opts)

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
			return writer.WriteRBACAuditResult(result)
		},
	}

	cmd.Flags().StringVar(&checks, "checks", "", "Comma-separated list of checks to run (e.g., RBAC001,RBAC002)")
	cmd.Flags().StringVar(&skipChecks, "skip", "", "Comma-separated list of checks to skip")

	return cmd
}

func cloudAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "cloud-audit",
		Short: "Audit cloud IAM configurations",
		Long: `Analyze cloud IAM roles for security issues including privilege escalation,
cross-account access, and overly permissive policies.

Requires --include-cloud flag and appropriate cloud credentials.

Examples:
  idc cloud-audit -A --include-cloud --aws-region us-west-2
  idc cloud-audit -A --include-cloud --azure-subscription <sub-id>`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			if !includeCloud {
				fmt.Println("Cloud audit requires --include-cloud flag.")
				fmt.Println("Example: idc cloud-audit -A --include-cloud --aws-region us-west-2")
				return nil
			}

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			result := analysis.AnalyzeCloudIAM(g)

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
			return writer.WriteCloudAuditResult(result)
		},
	}

	return cmd
}

func podSecurityCmd() *cobra.Command {
	var checks string
	var skipChecks string

	cmd := &cobra.Command{
		Use:   "pod-security",
		Short: "Run pod security audit",
		Long: `Analyze workload configurations for security issues such as privileged containers,
host access, dangerous capabilities, and missing security context.

Checks for Pod Security Standards (PSS) violations and common misconfigurations.

Examples:
  idc pod-security -A
  idc pod-security -n prod
  idc pod-security -A --checks PSS001,PSS002
  idc pod-security -A --skip-checks PSS010`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.PodSecurityOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}

			if allNamespaces {
				opts.Namespace = ""
			}

			if checks != "" {
				opts.ChecksToRun = strings.Split(checks, ",")
			}
			if skipChecks != "" {
				opts.SkipChecks = strings.Split(skipChecks, ",")
			}

			result := analysis.RunPodSecurityAudit(g, opts)

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
			return writer.WritePodSecurityResult(result)
		},
	}

	cmd.Flags().StringVar(&checks, "checks", "", "Comma-separated list of checks to run (e.g., PSS001,PSS002)")
	cmd.Flags().StringVar(&skipChecks, "skip-checks", "", "Comma-separated list of checks to skip")

	return cmd
}

func networkPolicyCmd() *cobra.Command {
	var checks string
	var skipChecks string

	cmd := &cobra.Command{
		Use:   "network-policy",
		Short: "Run network policy audit",
		Long: `Analyze network policies for security issues such as missing policies,
externally exposed workloads, and overly permissive rules.

Examples:
  idc network-policy -A
  idc network-policy -n prod
  idc network-policy -A --checks NET001,NET002
  idc network-policy -A --skip-checks NET007`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.NetworkPolicyOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}

			if allNamespaces {
				opts.Namespace = ""
			}

			if checks != "" {
				opts.ChecksToRun = strings.Split(checks, ",")
			}
			if skipChecks != "" {
				opts.SkipChecks = strings.Split(skipChecks, ",")
			}

			result := analysis.RunNetworkPolicyAudit(g, opts)

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))
			return writer.WriteNetworkPolicyResult(result)
		},
	}

	cmd.Flags().StringVar(&checks, "checks", "", "Comma-separated list of checks to run (e.g., NET001,NET002)")
	cmd.Flags().StringVar(&skipChecks, "skip-checks", "", "Comma-separated list of checks to skip")

	return cmd
}

func attackPathCmd() *cobra.Command {
	var workload string
	var all bool
	var maxDepth int

	cmd := &cobra.Command{
		Use:   "attack-path",
		Short: "Visualize attack paths from workloads",
		Long: `Analyze and visualize potential attack paths from compromised workloads.
Traces paths through RBAC, secrets access, pod creation, and cloud IAM.

Each attack path shows step-by-step techniques an attacker could use,
with MITRE ATT&CK references and mitigation recommendations.

Examples:
  idc attack-path --all -A
  idc attack-path --workload deployment/api-server -n prod
  idc attack-path --all -A --include-cloud --aws-region us-west-2
  idc attack-path --all -A -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.AttackPathOptions{
				MaxDepth:       maxDepth,
				IncludeCloud:   includeCloud,
				IncludePrivesc: true,
				Namespace:      namespace,
			}

			if allNamespaces {
				opts.Namespace = ""
			}

			writer := output.NewWriter(os.Stdout, output.Format(outputFormat))

			if all {
				results, err := analysis.FindAllAttackPaths(g, opts)
				if err != nil {
					return fmt.Errorf("attack path analysis failed: %w", err)
				}
				return writer.WriteAttackPathResults(results)
			}

			if workload == "" {
				return fmt.Errorf("--workload or --all is required")
			}

			nodeID := resolveWorkloadNodeID(g, workload, namespace)
			result, err := analysis.FindAttackPaths(g, nodeID, opts)
			if err != nil {
				return fmt.Errorf("attack path analysis failed: %w", err)
			}

			if result == nil {
				return fmt.Errorf("workload not found: %s", workload)
			}

			return writer.WriteAttackPathResults([]*analysis.AttackPathResult{result})
		},
	}

	cmd.Flags().StringVarP(&workload, "workload", "w", "", "Workload to analyze")
	cmd.Flags().BoolVar(&all, "all", false, "Analyze all workloads")
	cmd.Flags().IntVar(&maxDepth, "depth", 5, "Maximum path depth to search")

	return cmd
}

func dashboardCmd() *cobra.Command {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "dashboard",
		Short: "Generate unified security dashboard",
		Long: `Generate a comprehensive security dashboard combining all analysis results:
- Blast radius analysis
- Attack path visualization
- RBAC security audit
- Pod security analysis
- Network policy audit
- Cloud IAM audit (if --include-cloud)

Outputs an interactive HTML dashboard with tabs for each analysis type.

Examples:
  idc dashboard -A -o report.html
  idc dashboard -A --include-cloud --aws-region us-west-2 -o report.html`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			fmt.Fprintln(os.Stderr, "Collecting cluster data...")
			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			// Determine output destination
			var w *os.File
			if outputFile != "" {
				w, err = os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer w.Close()
			} else {
				w = os.Stdout
			}

			// Run all analyses
			fmt.Fprintln(os.Stderr, "Running blast radius analysis...")
			blastResults, _ := analysis.AllWorkloadBlastRadius(g)

			fmt.Fprintln(os.Stderr, "Running attack path analysis...")
			attackOpts := analysis.AttackPathOptions{
				MaxDepth:       5,
				IncludeCloud:   includeCloud,
				IncludePrivesc: true,
			}
			attackResults, _ := analysis.FindAllAttackPaths(g, attackOpts)

			fmt.Fprintln(os.Stderr, "Running RBAC audit...")
			rbacResult := analysis.RunRBACAudit(g, analysis.RBACAuditOptions{})

			fmt.Fprintln(os.Stderr, "Running pod security audit...")
			podSecResult := analysis.RunPodSecurityAudit(g, analysis.PodSecurityOptions{})

			fmt.Fprintln(os.Stderr, "Running network policy audit...")
			netPolResult := analysis.RunNetworkPolicyAudit(g, analysis.NetworkPolicyOptions{})

			var cloudResult *analysis.CloudIAMAuditResult
			if includeCloud {
				fmt.Fprintln(os.Stderr, "Running cloud IAM audit...")
				cloudResult = analysis.AnalyzeCloudIAM(g)
			}

			fmt.Fprintln(os.Stderr, "Running permissions audit...")
			permissionsData := collectPermissionsData(g)

			fmt.Fprintln(os.Stderr, "Generating dashboard...")

			// Generate unified dashboard
			dashboard := output.NewDashboard(w)
			err = dashboard.Generate(output.DashboardData{
				BlastResults:   blastResults,
				AttackPaths:    attackResults,
				RBACAudit:      rbacResult,
				PodSecurity:    podSecResult,
				NetworkPolicy:  netPolResult,
				CloudAudit:     cloudResult,
				Permissions:    permissionsData,
				GraphStats:     g.Stats(),
				Graph:          g,
			})

			if err != nil {
				return fmt.Errorf("failed to generate dashboard: %w", err)
			}

			if outputFile != "" {
				fmt.Fprintf(os.Stderr, "Dashboard saved to: %s\n", outputFile)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Output file path (default: stdout)")

	return cmd
}

// collectPermissionsData runs WhoCan queries for dangerous permissions
func collectPermissionsData(g *graph.Graph) *output.PermissionsData {
	data := &output.PermissionsData{}

	// Get all namespaces from the graph
	namespaces := make(map[string]bool)
	for _, node := range g.GetNodesByType(graph.NodeWorkload) {
		namespaces[node.Namespace] = true
	}
	for _, node := range g.GetNodesByType(graph.NodeServiceAccount) {
		namespaces[node.Namespace] = true
	}

	// Query dangerous permissions across namespaces
	for ns := range namespaces {
		// Who can get secrets
		if result, err := analysis.WhoCan(g, analysis.WhoCanQuery{
			Verb: "get", Resource: "secrets", Namespace: ns,
		}); err == nil && len(result.Subjects) > 0 {
			data.SecretAccess = append(data.SecretAccess, result)
		}

		// Who can exec into pods
		if result, err := analysis.WhoCan(g, analysis.WhoCanQuery{
			Verb: "create", Resource: "pods", Subresource: "exec", Namespace: ns,
		}); err == nil && len(result.Subjects) > 0 {
			data.PodExec = append(data.PodExec, result)
		}

		// Who can create pods
		if result, err := analysis.WhoCan(g, analysis.WhoCanQuery{
			Verb: "create", Resource: "pods", Namespace: ns,
		}); err == nil && len(result.Subjects) > 0 {
			data.PodCreate = append(data.PodCreate, result)
		}

		// Who can delete pods
		if result, err := analysis.WhoCan(g, analysis.WhoCanQuery{
			Verb: "delete", Resource: "pods", Namespace: ns,
		}); err == nil && len(result.Subjects) > 0 {
			data.PodDelete = append(data.PodDelete, result)
		}
	}

	// Cluster-wide dangerous permissions
	// Who can create clusterrolebindings
	if result, err := analysis.WhoCan(g, analysis.WhoCanQuery{
		Verb: "create", Resource: "clusterrolebindings", APIGroup: "rbac.authorization.k8s.io",
	}); err == nil && len(result.Subjects) > 0 {
		data.ClusterAdmin = append(data.ClusterAdmin, result)
	}

	// Who can create rolebindings
	if result, err := analysis.WhoCan(g, analysis.WhoCanQuery{
		Verb: "create", Resource: "rolebindings", APIGroup: "rbac.authorization.k8s.io",
	}); err == nil && len(result.Subjects) > 0 {
		data.RoleBindings = append(data.RoleBindings, result)
	}

	// Who can impersonate
	if result, err := analysis.WhoCan(g, analysis.WhoCanQuery{
		Verb: "impersonate", Resource: "users",
	}); err == nil && len(result.Subjects) > 0 {
		data.Impersonate = append(data.Impersonate, result)
	}
	if result, err := analysis.WhoCan(g, analysis.WhoCanQuery{
		Verb: "impersonate", Resource: "serviceaccounts",
	}); err == nil && len(result.Subjects) > 0 {
		data.Impersonate = append(data.Impersonate, result)
	}

	// Build dangerous permissions summary
	data.DangerousPerms = buildDangerousPermsSummary(data)

	return data
}

// buildDangerousPermsSummary creates a consolidated list of dangerous permissions
func buildDangerousPermsSummary(data *output.PermissionsData) []output.DangerousPermission {
	var perms []output.DangerousPermission
	seen := make(map[string]bool)

	addPerm := func(subject, kind, ns, permission, severity, details string) {
		key := subject + "|" + ns + "|" + permission
		if seen[key] {
			return
		}
		seen[key] = true
		perms = append(perms, output.DangerousPermission{
			Subject:     subject,
			SubjectKind: kind,
			Namespace:   ns,
			Permission:  permission,
			Severity:    severity,
			Details:     details,
		})
	}

	// Process secret access
	for _, result := range data.SecretAccess {
		for _, subj := range result.Subjects {
			ns := result.Namespace
			if ns == "" {
				ns = "cluster-wide"
			}
			addPerm(subj.Name, subj.Kind, ns, "get secrets", "high", "Can read secrets in "+ns)
		}
	}

	// Process pod exec
	for _, result := range data.PodExec {
		for _, subj := range result.Subjects {
			ns := result.Namespace
			if ns == "" {
				ns = "cluster-wide"
			}
			addPerm(subj.Name, subj.Kind, ns, "exec pods", "critical", "Can execute commands in pods")
		}
	}

	// Process cluster admin permissions
	for _, result := range data.ClusterAdmin {
		for _, subj := range result.Subjects {
			addPerm(subj.Name, subj.Kind, "cluster-wide", "create clusterrolebindings", "critical", "Can grant cluster-admin access")
		}
	}

	// Process impersonate
	for _, result := range data.Impersonate {
		for _, subj := range result.Subjects {
			addPerm(subj.Name, subj.Kind, "cluster-wide", "impersonate", "critical", "Can impersonate other identities")
		}
	}

	return perms
}
