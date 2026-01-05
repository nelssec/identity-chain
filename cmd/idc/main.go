package main

import (
	"context"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/audit"
	"github.com/nelssec/identity-chain/pkg/checks"
	"github.com/nelssec/identity-chain/pkg/collector"
	"github.com/nelssec/identity-chain/pkg/collector/cloud"
	"github.com/nelssec/identity-chain/pkg/graph"
	"github.com/nelssec/identity-chain/pkg/output"
	"github.com/nelssec/identity-chain/pkg/remediation"
	"github.com/nelssec/identity-chain/pkg/store"
	"github.com/nelssec/identity-chain/pkg/watch"
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
	rootCmd.AddCommand(generateCmd())
	rootCmd.AddCommand(saLifecycleCmd())
	rootCmd.AddCommand(sccCmd())
	rootCmd.AddCommand(remediateCmd())
	rootCmd.AddCommand(checkCmd())
	rootCmd.AddCommand(historyCmd())
	rootCmd.AddCommand(trendCmd())
	rootCmd.AddCommand(clustersCmd())
	rootCmd.AddCommand(watchCmd())

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

	if collector.IsOpenShiftCluster(ctx, opts) {
		osCollector, err := collector.NewOpenShiftCollector(opts)
		if err == nil {
			_ = osCollector.Collect(ctx, builder)
		}
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
	var cwLogGroup string

	cmd := &cobra.Command{
		Use:   "unused",
		Short: "Find unused RBAC permissions",
		Long: `Analyze audit logs to find permissions granted but never used.
This helps identify overprivileged service accounts.

Examples:
  idc unused --since 30d --audit-source file --audit-path /var/log/audit/
  idc unused --since 7d --audit-source elasticsearch --es-endpoint http://es:9200
  idc unused --since 30d --audit-source cloudwatch --log-group /aws/eks/my-cluster/cluster --aws-region us-west-2
  idc unused --since 30d --audit-source gcp --gcp-project my-project
  idc unused --since 30d --audit-source azure --azure-subscription <sub-id>`,
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
			case "cloudwatch":
				cwSource, err := audit.NewCloudWatchSource(ctx, audit.CloudWatchConfig{
					LogGroup: cwLogGroup,
					Region:   awsRegion,
				})
				if err != nil {
					return fmt.Errorf("failed to create CloudWatch source: %w", err)
				}
				source = cwSource
			case "gcp", "gcp-logging":
				gcpSource, err := audit.NewGCPCloudLoggingSource(ctx, audit.GCPCloudLoggingConfig{
					ProjectID: gcpProject,
				})
				if err != nil {
					return fmt.Errorf("failed to create GCP Cloud Logging source: %w", err)
				}
				source = gcpSource
			case "azure", "azure-log-analytics":
				azSource, err := audit.NewAzureLogAnalyticsSource(azureSubID)
				if err != nil {
					return fmt.Errorf("failed to create Azure Log Analytics source: %w", err)
				}
				source = azSource
			default:
				return fmt.Errorf("unsupported audit source: %s (supported: file, elasticsearch, cloudwatch, gcp, azure)", auditSource)
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
	cmd.Flags().StringVar(&auditSource, "audit-source", "file", "Audit log source: file, elasticsearch, cloudwatch")
	cmd.Flags().StringVar(&auditPath, "audit-path", "/var/log/kubernetes/audit/", "Path to audit log files")
	cmd.Flags().StringVar(&esEndpoint, "es-endpoint", "", "Elasticsearch endpoint URL")
	cmd.Flags().StringVar(&esIndex, "es-index", "kubernetes-audit-*", "Elasticsearch index pattern")
	cmd.Flags().StringVar(&cwLogGroup, "log-group", "", "CloudWatch log group (e.g., /aws/eks/cluster-name/cluster)")

	return cmd
}

func auditCmd() *cobra.Command {
	var auditSource string
	var auditPath string
	var esEndpoint string
	var esIndex string
	var cwLogGroup string
	var since string
	var realtime bool

	cmd := &cobra.Command{
		Use:   "audit",
		Short: "Analyze Kubernetes audit logs",
		Long: `Parse and analyze Kubernetes audit logs to track permission usage.

Examples:
  idc audit --since 24h --audit-source file --audit-path /var/log/audit/
  idc audit --realtime --audit-source elasticsearch
  idc audit --since 24h --audit-source cloudwatch --log-group /aws/eks/my-cluster/cluster --aws-region us-west-2
  idc audit --since 24h --audit-source gcp --gcp-project my-project
  idc audit --since 24h --audit-source azure --azure-subscription <sub-id>`,
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
			case "cloudwatch":
				cwSource, err := audit.NewCloudWatchSource(ctx, audit.CloudWatchConfig{
					LogGroup: cwLogGroup,
					Region:   awsRegion,
				})
				if err != nil {
					return fmt.Errorf("failed to create CloudWatch source: %w", err)
				}
				source = cwSource
			case "gcp", "gcp-logging":
				gcpSource, err := audit.NewGCPCloudLoggingSource(ctx, audit.GCPCloudLoggingConfig{
					ProjectID: gcpProject,
				})
				if err != nil {
					return fmt.Errorf("failed to create GCP Cloud Logging source: %w", err)
				}
				source = gcpSource
			case "azure", "azure-log-analytics":
				azSource, err := audit.NewAzureLogAnalyticsSource(azureSubID)
				if err != nil {
					return fmt.Errorf("failed to create Azure Log Analytics source: %w", err)
				}
				source = azSource
			default:
				return fmt.Errorf("unsupported audit source: %s (supported: file, elasticsearch, loki, cloudwatch, gcp, azure)", auditSource)
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
	cmd.Flags().StringVar(&auditSource, "audit-source", "file", "Audit log source: file, elasticsearch, loki, cloudwatch")
	cmd.Flags().StringVar(&auditPath, "audit-path", "/var/log/kubernetes/audit/", "Path to audit log files")
	cmd.Flags().StringVar(&esEndpoint, "es-endpoint", "", "Elasticsearch/Loki endpoint URL")
	cmd.Flags().StringVar(&cwLogGroup, "log-group", "", "CloudWatch log group (e.g., /aws/eks/cluster-name/cluster)")
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
	var auditSource string
	var auditPath string
	var esEndpoint string
	var esIndex string
	var cwLogGroup string
	var auditSince string

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
- Unused permissions (if --audit-source specified)

Outputs an interactive HTML dashboard with tabs for each analysis type.

Examples:
  idc dashboard -A -f report.html
  idc dashboard -A --include-cloud --aws-region us-west-2 -f report.html
  idc dashboard -A --audit-source cloudwatch --log-group /aws/eks/cluster/cluster --aws-region us-west-2 -f report.html
  idc dashboard -A --audit-source gcp --gcp-project my-project -f report.html`,
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

			fmt.Fprintln(os.Stderr, "Running SCC analysis...")
			sccResult := analysis.AnalyzeSCCs(g)

			fmt.Fprintln(os.Stderr, "Running permissions audit...")
			permissionsData := collectPermissionsData(g)

			// Run unused permissions analysis if audit source is configured
			var unusedPerms []audit.UnusedPermission
			if auditSource != "" {
				fmt.Fprintln(os.Stderr, "Analyzing audit logs for unused permissions...")
				unusedPerms = collectUnusedPermissions(ctx, g, auditSource, auditPath, esEndpoint, esIndex, cwLogGroup, auditSince)
			}

			fmt.Fprintln(os.Stderr, "Generating CIS compliance summary...")
			var rbacFindings []analysis.RBACFinding
			var podSecFindings []analysis.PodSecurityFinding
			var netPolFindings []analysis.NetworkPolicyFinding
			if rbacResult != nil {
				rbacFindings = rbacResult.Findings
			}
			if podSecResult != nil {
				podSecFindings = podSecResult.Findings
			}
			if netPolResult != nil {
				netPolFindings = netPolResult.Findings
			}
			cisCompliance := analysis.GenerateCISComplianceSummary(rbacFindings, podSecFindings, netPolFindings)

			fmt.Fprintln(os.Stderr, "Generating dashboard...")

			dashboard := output.NewDashboard(w)
			err = dashboard.Generate(output.DashboardData{
				BlastResults:      blastResults,
				AttackPaths:       attackResults,
				RBACAudit:         rbacResult,
				PodSecurity:       podSecResult,
				NetworkPolicy:     netPolResult,
				CloudAudit:        cloudResult,
				Permissions:       permissionsData,
				UnusedPermissions: unusedPerms,
				SCCAnalysis:       sccResult,
				CISCompliance:     cisCompliance,
				GraphStats:        g.Stats(),
				Graph:             g,
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
	cmd.Flags().StringVar(&auditSource, "audit-source", "", "Audit log source: file, elasticsearch, cloudwatch, gcp, azure")
	cmd.Flags().StringVar(&auditPath, "audit-path", "/var/log/kubernetes/audit/", "Path to audit log files")
	cmd.Flags().StringVar(&esEndpoint, "es-endpoint", "", "Elasticsearch endpoint URL")
	cmd.Flags().StringVar(&esIndex, "es-index", "kubernetes-audit-*", "Elasticsearch index pattern")
	cmd.Flags().StringVar(&cwLogGroup, "log-group", "", "CloudWatch log group")
	cmd.Flags().StringVar(&auditSince, "audit-since", "30d", "Time period for audit analysis (e.g., 7d, 30d)")

	return cmd
}

// collectUnusedPermissions runs audit log analysis and returns unused permissions
func collectUnusedPermissions(ctx context.Context, g *graph.Graph, auditSource, auditPath, esEndpoint, esIndex, cwLogGroup, since string) []audit.UnusedPermission {
	var source audit.Source
	var err error

	switch auditSource {
	case "file":
		source = audit.NewDirectorySource(auditPath, "*.log")
	case "elasticsearch":
		source = audit.NewElasticsearchSource(esEndpoint, esIndex, "", "")
	case "cloudwatch":
		source, err = audit.NewCloudWatchSource(ctx, audit.CloudWatchConfig{
			LogGroup: cwLogGroup,
			Region:   awsRegion,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create CloudWatch source: %v\n", err)
			return nil
		}
	case "gcp", "gcp-logging":
		source, err = audit.NewGCPCloudLoggingSource(ctx, audit.GCPCloudLoggingConfig{
			ProjectID: gcpProject,
		})
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create GCP Cloud Logging source: %v\n", err)
			return nil
		}
	case "azure", "azure-log-analytics":
		source, err = audit.NewAzureLogAnalyticsSource(azureSubID)
		if err != nil {
			fmt.Fprintf(os.Stderr, "Warning: Failed to create Azure Log Analytics source: %v\n", err)
			return nil
		}
	default:
		fmt.Fprintf(os.Stderr, "Warning: Unknown audit source: %s\n", auditSource)
		return nil
	}
	defer source.Close()

	duration, err := parseDuration(since)
	if err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Invalid duration %s: %v\n", since, err)
		duration = 30 * 24 * time.Hour // default to 30 days
	}

	analyzer := audit.NewAnalyzer(source, g)
	queryOpts := audit.QueryOptions{
		StartTime:     time.Now().Add(-duration),
		EndTime:       time.Now(),
		IncludeSystem: includeSystem,
	}

	if err := analyzer.Analyze(ctx, queryOpts); err != nil {
		fmt.Fprintf(os.Stderr, "Warning: Audit analysis failed: %v\n", err)
		return nil
	}

	return analyzer.GetUnusedPermissions(duration)
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

	for _, result := range data.Impersonate {
		for _, subj := range result.Subjects {
			addPerm(subj.Name, subj.Kind, "cluster-wide", "impersonate", "critical", "Can impersonate other identities")
		}
	}

	return perms
}

func generateCmd() *cobra.Command {
	var auditSource string
	var auditPath string
	var esEndpoint string
	var esIndex string
	var cwLogGroup string
	var since string
	var serviceAccount string
	var outputFile string

	cmd := &cobra.Command{
		Use:   "generate",
		Short: "Generate least-privilege RBAC roles from audit logs",
		Long: `Analyze audit logs to generate minimal RBAC roles based on actual usage.
This creates Role/ClusterRole YAML that grants only the permissions actually used.

Examples:
  idc generate -A --audit-source cloudwatch --log-group /aws/eks/cluster/cluster --aws-region us-west-2
  idc generate -A --audit-source gcp --gcp-project my-project --since 30d
  idc generate -A --audit-source file --audit-path /var/log/audit/ -f roles.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			fmt.Fprintln(os.Stderr, "Collecting cluster data...")
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
			case "cloudwatch":
				source, err = audit.NewCloudWatchSource(ctx, audit.CloudWatchConfig{
					LogGroup: cwLogGroup,
					Region:   awsRegion,
				})
				if err != nil {
					return fmt.Errorf("failed to create CloudWatch source: %w", err)
				}
			case "gcp", "gcp-logging":
				source, err = audit.NewGCPCloudLoggingSource(ctx, audit.GCPCloudLoggingConfig{
					ProjectID: gcpProject,
				})
				if err != nil {
					return fmt.Errorf("failed to create GCP source: %w", err)
				}
			case "azure", "azure-log-analytics":
				source, err = audit.NewAzureLogAnalyticsSource(azureSubID)
				if err != nil {
					return fmt.Errorf("failed to create Azure source: %w", err)
				}
			default:
				return fmt.Errorf("--audit-source is required (file, elasticsearch, cloudwatch, gcp, azure)")
			}
			defer source.Close()

			duration, err := parseDuration(since)
			if err != nil {
				return fmt.Errorf("invalid duration: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Analyzing audit logs...")
			analyzer := audit.NewAnalyzer(source, g)
			queryOpts := audit.QueryOptions{
				StartTime:     time.Now().Add(-duration),
				EndTime:       time.Now(),
				IncludeSystem: includeSystem,
			}

			if err := analyzer.Analyze(ctx, queryOpts); err != nil {
				return fmt.Errorf("failed to analyze audit logs: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Generating least-privilege roles...")

			var roles []audit.LeastPrivilegeRole
			if serviceAccount != "" {
				parts := strings.SplitN(serviceAccount, "/", 2)
				var ns, name string
				if len(parts) == 2 {
					ns = parts[0]
					name = parts[1]
				} else {
					ns = namespace
					name = serviceAccount
				}
				role := analyzer.GenerateLeastPrivilegeRoleForSA(name, ns)
				if role != nil {
					roles = append(roles, *role)
				}
			} else {
				roles = analyzer.GenerateLeastPrivilegeRoles()
			}

			if len(roles) == 0 {
				fmt.Println("No roles generated - no service account activity found in audit logs")
				return nil
			}

			var out *os.File
			if outputFile != "" {
				out, err = os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer out.Close()
			} else {
				out = os.Stdout
			}

			fmt.Fprintf(os.Stderr, "\n=== Least-Privilege Role Generation ===\n\n")
			fmt.Fprintf(os.Stderr, "Generated %d roles from audit log analysis\n\n", len(roles))

			for _, role := range roles {
				fmt.Fprintf(os.Stderr, "%-50s %s → %d perms (%.0f%% reduction)\n",
					role.ServiceAccount,
					role.RoleKind,
					role.Reduction.NewPermissions,
					role.Reduction.PercentReduction)

				fmt.Fprintln(out, role.YAML)
			}

			if outputFile != "" {
				fmt.Fprintf(os.Stderr, "\nYAML saved to: %s\n", outputFile)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&auditSource, "audit-source", "", "Audit log source: file, elasticsearch, cloudwatch, gcp, azure")
	cmd.Flags().StringVar(&auditPath, "audit-path", "/var/log/kubernetes/audit/", "Path to audit log files")
	cmd.Flags().StringVar(&esEndpoint, "es-endpoint", "", "Elasticsearch endpoint URL")
	cmd.Flags().StringVar(&esIndex, "es-index", "kubernetes-audit-*", "Elasticsearch index pattern")
	cmd.Flags().StringVar(&cwLogGroup, "log-group", "", "CloudWatch log group")
	cmd.Flags().StringVar(&since, "since", "30d", "Time period to analyze (e.g., 7d, 30d)")
	cmd.Flags().StringVar(&serviceAccount, "service-account", "", "Generate role for specific SA (namespace/name)")
	cmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Output file for YAML (default: stdout)")

	return cmd
}

func saLifecycleCmd() *cobra.Command {
	var staleThreshold int

	cmd := &cobra.Command{
		Use:   "sa-lifecycle",
		Short: "Analyze service account lifecycle and find orphaned/stale SAs",
		Long: `Identify service accounts that may need cleanup:
- Orphaned: SAs with RBAC bindings but not used by any workload
- Unused: SAs not referenced by any workload and no bindings
- Unbound: SAs used by workloads but have no RBAC permissions

Examples:
  idc sa-lifecycle -A
  idc sa-lifecycle -A --include-system
  idc sa-lifecycle -n production`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			result := analysis.AnalyzeSALifecycle(g, analysis.SALifecycleOptions{
				StaleThresholdDays: staleThreshold,
				IncludeSystem:      includeSystem,
			})

			fmt.Printf("=== Service Account Lifecycle Analysis ===\n\n")
			fmt.Printf("Total Service Accounts: %d\n", result.Summary.TotalSAs)
			fmt.Printf("Orphaned: %d\n", result.Summary.OrphanedCount)
			fmt.Printf("Unbound (used but no perms): %d\n", result.Summary.UnboundCount)
			fmt.Printf("Healthy: %d\n\n", result.Summary.HealthyCount)

			if len(result.OrphanedSAs) > 0 {
				fmt.Printf("ORPHANED SERVICE ACCOUNTS\n")
				fmt.Printf("%-40s %-20s %s\n", "SERVICE ACCOUNT", "NAMESPACE", "REASON")
				fmt.Printf("%s\n", strings.Repeat("─", 100))
				for _, sa := range result.OrphanedSAs {
					fmt.Printf("%-40s %-20s %s\n", sa.Name, sa.Namespace, sa.Reason)
				}
				fmt.Println()
			}

			if len(result.UnboundSAs) > 0 {
				fmt.Printf("UNBOUND SERVICE ACCOUNTS (used by workloads but no RBAC)\n")
				fmt.Printf("%-40s %-20s %s\n", "SERVICE ACCOUNT", "NAMESPACE", "USED BY")
				fmt.Printf("%s\n", strings.Repeat("─", 100))
				for _, sa := range result.UnboundSAs {
					usedBy := strings.Join(sa.UsedBy, ", ")
					if len(usedBy) > 40 {
						usedBy = usedBy[:37] + "..."
					}
					fmt.Printf("%-40s %-20s %s\n", sa.Name, sa.Namespace, usedBy)
				}
				fmt.Println()
			}

			if len(result.OrphanedSAs) == 0 && len(result.UnboundSAs) == 0 {
				fmt.Println("No orphaned or problematic service accounts found.")
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&staleThreshold, "stale-days", 30, "Days of inactivity to consider SA stale")

	return cmd
}

func sccCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "scc",
		Short: "Analyze OpenShift Security Context Constraints",
		Long: `Analyze OpenShift SCCs (Security Context Constraints) for security issues.
Identifies privileged SCCs, risky bindings, and potential escalation paths.

This command only works on OpenShift clusters.

Examples:
  idc scc -A
  idc scc -A --include-system`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			opts := collector.Options{
				Namespace:      namespace,
				AllNamespaces:  allNamespaces,
				IncludeSystem:  includeSystem,
				KubeConfigPath: kubeconfig,
				KubeContext:    kubecontext,
			}

			if !collector.IsOpenShiftCluster(ctx, opts) {
				fmt.Println("This command requires an OpenShift cluster.")
				fmt.Println("SCCs are not available on standard Kubernetes.")
				return nil
			}

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			result := analysis.AnalyzeSCCs(g)

			if len(result.SCCs) == 0 {
				fmt.Println("No SCCs found in the cluster.")
				return nil
			}

			fmt.Printf("=== OpenShift SCC Analysis ===\n\n")
			fmt.Printf("Total SCCs: %d\n", result.Summary.TotalSCCs)
			fmt.Printf("Privileged SCCs: %d\n", result.Summary.PrivilegedSCCs)
			fmt.Printf("Total Bindings: %d\n", result.Summary.TotalBindings)
			fmt.Printf("Risky Bindings: %d\n", result.Summary.RiskyBindings)
			fmt.Printf("Escalation Paths: %d\n\n", result.Summary.EscalationPaths)

			fmt.Printf("SCC RISK LEVELS\n")
			fmt.Printf("%-30s %-10s %-6s %s\n", "SCC NAME", "RISK", "SCORE", "FLAGS")
			fmt.Printf("%s\n", strings.Repeat("─", 100))
			for _, scc := range result.SCCs {
				flags := strings.Join(scc.AllowedFlags, ", ")
				if len(flags) > 40 {
					flags = flags[:37] + "..."
				}
				fmt.Printf("%-30s %-10s %-6d %s\n", scc.Name, scc.RiskLevel, scc.RiskScore, flags)
			}
			fmt.Println()

			if len(result.RiskyBindings) > 0 {
				fmt.Printf("RISKY SCC BINDINGS\n")
				fmt.Printf("%-20s %-15s %-30s %s\n", "SCC", "TYPE", "SUBJECT", "RISK")
				fmt.Printf("%s\n", strings.Repeat("─", 100))
				for _, b := range result.RiskyBindings {
					subject := b.SubjectName
					if b.SubjectNS != "" {
						subject = b.SubjectNS + "/" + b.SubjectName
					}
					fmt.Printf("%-20s %-15s %-30s %s\n",
						truncate(b.SCCName, 20),
						b.SubjectType,
						truncate(subject, 30),
						b.RiskLevel)
				}
				fmt.Println()
			}

			if len(result.EscalationPaths) > 0 {
				fmt.Printf("SCC ESCALATION PATHS\n")
				fmt.Printf("%-30s %-20s %-20s %s\n", "SOURCE", "TARGET SCC", "VIA", "RISK")
				fmt.Printf("%s\n", strings.Repeat("─", 100))
				for _, p := range result.EscalationPaths {
					fmt.Printf("%-30s %-20s %-20s %s\n",
						truncate(p.Source, 30),
						truncate(p.TargetSCC, 20),
						truncate(p.Via, 20),
						p.RiskLevel)
				}
				fmt.Println()
			}

			return nil
		},
	}

	return cmd
}

func remediateCmd() *cobra.Command {
	var outputFile string
	var minSeverity string
	var remType string
	var manifestsOnly bool

	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Generate fix manifests for security findings",
		Long: `Generate Kubernetes manifests to remediate security findings.
Creates YAML that can be applied to fix RBAC, pod security, and network policy issues.

Examples:
  idc remediate -A -f fixes.yaml
  idc remediate -A --severity critical
  idc remediate -A --type rbac -f rbac-fixes.yaml
  idc remediate -A --manifests-only`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			fmt.Fprintln(os.Stderr, "Collecting cluster data...")
			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Running security audits...")
			rbacResult := analysis.RunRBACAudit(g, analysis.RBACAuditOptions{
				IncludeSystem: includeSystem,
			})
			podSecResult := analysis.RunPodSecurityAudit(g, analysis.PodSecurityOptions{
				IncludeSystem: includeSystem,
			})
			netPolResult := analysis.RunNetworkPolicyAudit(g, analysis.NetworkPolicyOptions{
				IncludeSystem: includeSystem,
			})

			var rbacFindings []analysis.RBACFinding
			var podSecFindings []analysis.PodSecurityFinding
			var netPolFindings []analysis.NetworkPolicyFinding

			if rbacResult != nil {
				rbacFindings = rbacResult.Findings
			}
			if podSecResult != nil {
				podSecFindings = podSecResult.Findings
			}
			if netPolResult != nil {
				netPolFindings = netPolResult.Findings
			}

			fmt.Fprintln(os.Stderr, "Generating remediations...")
			result := remediation.GenerateAllRemediations(rbacFindings, podSecFindings, netPolFindings)

			if minSeverity != "" {
				result = remediation.FilterBySeverity(result, minSeverity)
			}

			if remType != "" {
				var rt remediation.RemediationType
				switch remType {
				case "rbac":
					rt = remediation.RemediationRBAC
				case "pod-security", "podsecurity":
					rt = remediation.RemediationPodSecurity
				case "network-policy", "networkpolicy":
					rt = remediation.RemediationNetworkPolicy
				case "service-account", "serviceaccount":
					rt = remediation.RemediationServiceAccount
				default:
					return fmt.Errorf("unknown remediation type: %s (use: rbac, pod-security, network-policy)", remType)
				}
				result = remediation.FilterByType(result, rt)
			}

			if !allNamespaces && namespace != "default" {
				result = remediation.FilterByNamespace(result, namespace)
			}

			var out *os.File
			if outputFile != "" {
				out, err = os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer out.Close()
			} else {
				out = os.Stdout
			}

			if manifestsOnly {
				fmt.Fprint(out, result.CombinedManifests)
				if outputFile != "" {
					fmt.Fprintf(os.Stderr, "Manifests saved to: %s\n", outputFile)
				}
				return nil
			}

			fmt.Fprintf(os.Stderr, "\n=== Remediation Summary ===\n\n")
			fmt.Fprintf(os.Stderr, "Total Findings:    %d\n", result.TotalFindings)
			fmt.Fprintf(os.Stderr, "Remediable:        %d\n", result.RemediableCount)
			fmt.Fprintf(os.Stderr, "Non-remediable:    %d\n\n", result.NonRemediable)

			bySeverity := make(map[string]int)
			byType := make(map[remediation.RemediationType]int)
			for _, r := range result.Remediations {
				bySeverity[r.Severity]++
				byType[r.Type]++
			}

			fmt.Fprintf(os.Stderr, "By Severity:\n")
			for _, sev := range []string{"critical", "high", "medium", "low"} {
				if count := bySeverity[sev]; count > 0 {
					fmt.Fprintf(os.Stderr, "  %-10s %d\n", sev, count)
				}
			}

			fmt.Fprintf(os.Stderr, "\nBy Type:\n")
			for rt, count := range byType {
				fmt.Fprintf(os.Stderr, "  %-20s %d\n", rt, count)
			}
			fmt.Fprintln(os.Stderr)

			fmt.Fprintf(os.Stderr, "REMEDIATIONS\n")
			fmt.Fprintf(os.Stderr, "%-12s %-10s %-30s %-30s %s\n", "CHECK", "SEVERITY", "RESOURCE", "ACTION", "MANIFESTS")
			fmt.Fprintf(os.Stderr, "%s\n", strings.Repeat("─", 120))

			for _, r := range result.Remediations {
				resource := fmt.Sprintf("%s/%s", r.Resource.Kind, r.Resource.Name)
				if r.Resource.Namespace != "" {
					resource = r.Resource.Namespace + "/" + resource
				}
				if len(resource) > 30 {
					resource = resource[:27] + "..."
				}
				action := r.Action
				if len(action) > 30 {
					action = action[:27] + "..."
				}
				fmt.Fprintf(os.Stderr, "%-12s %-10s %-30s %-30s %d\n",
					r.CheckID, r.Severity, resource, action, len(r.Manifests))
			}

			fmt.Fprintln(os.Stderr)
			fmt.Fprintln(out, result.CombinedManifests)

			if outputFile != "" {
				fmt.Fprintf(os.Stderr, "Manifests saved to: %s\n", outputFile)
				fmt.Fprintf(os.Stderr, "\nTo apply: kubectl apply -f %s\n", outputFile)
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Output file for YAML manifests")
	cmd.Flags().StringVar(&minSeverity, "severity", "", "Minimum severity to include (critical, high, medium, low)")
	cmd.Flags().StringVar(&remType, "type", "", "Filter by type (rbac, pod-security, network-policy)")
	cmd.Flags().BoolVar(&manifestsOnly, "manifests-only", false, "Output only the YAML manifests")

	return cmd
}

func checkCmd() *cobra.Command {
	var configFile string
	var minSeverity string

	cmd := &cobra.Command{
		Use:   "check",
		Short: "Run custom security checks from YAML config",
		Long: `Run user-defined security checks against the cluster.
Custom checks are defined in a YAML configuration file.

Examples:
  idc check -A --config custom-checks.yaml
  idc check -A --config checks.yaml --severity high
  idc check -n prod --config prod-checks.yaml`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if configFile == "" {
				return fmt.Errorf("--config is required")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			config, err := checks.LoadCustomChecks(configFile)
			if err != nil {
				return fmt.Errorf("failed to load config: %w", err)
			}

			fmt.Fprintf(os.Stderr, "Loaded %d custom checks from %s\n", len(config.Checks), configFile)

			fmt.Fprintln(os.Stderr, "Collecting cluster data...")
			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			fmt.Fprintln(os.Stderr, "Running custom checks...")
			findings := checks.RunCustomChecks(g, config)

			if minSeverity != "" {
				findings = filterFindingsBySeverity(findings, minSeverity)
			}

			if len(findings) == 0 {
				fmt.Println("No findings from custom checks.")
				return nil
			}

			fmt.Printf("\n=== Custom Check Results ===\n\n")
			fmt.Printf("Total Findings: %d\n\n", len(findings))

			bySeverity := make(map[string]int)
			byCategory := make(map[string]int)
			for _, f := range findings {
				bySeverity[f.Severity]++
				byCategory[f.Category]++
			}

			fmt.Printf("By Severity:\n")
			for _, sev := range []string{"critical", "high", "medium", "low"} {
				if count := bySeverity[sev]; count > 0 {
					fmt.Printf("  %-10s %d\n", sev, count)
				}
			}

			fmt.Printf("\nBy Category:\n")
			for cat, count := range byCategory {
				fmt.Printf("  %-20s %d\n", cat, count)
			}

			fmt.Printf("\nFINDINGS\n")
			fmt.Printf("%-12s %-10s %-15s %-30s %s\n", "CHECK", "SEVERITY", "CATEGORY", "RESOURCE", "DETAILS")
			fmt.Printf("%s\n", strings.Repeat("─", 120))

			for _, f := range findings {
				for _, affected := range f.Affected {
					resource := affected.Name
					if affected.Namespace != "" {
						resource = affected.Namespace + "/" + resource
					}
					if len(resource) > 30 {
						resource = resource[:27] + "..."
					}
					details := affected.Details
					if len(details) > 40 {
						details = details[:37] + "..."
					}
					fmt.Printf("%-12s %-10s %-15s %-30s %s\n",
						f.CheckID, f.Severity, f.Category, resource, details)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&configFile, "config", "", "Path to custom checks YAML config file")
	cmd.Flags().StringVar(&minSeverity, "severity", "", "Minimum severity to include (critical, high, medium, low)")

	return cmd
}

func filterFindingsBySeverity(findings []checks.CustomFinding, minSeverity string) []checks.CustomFinding {
	severityOrder := map[string]int{
		"critical": 4,
		"high":     3,
		"medium":   2,
		"low":      1,
		"info":     0,
	}

	minLevel := severityOrder[minSeverity]
	if minLevel == 0 && minSeverity != "info" {
		minLevel = 2
	}

	var filtered []checks.CustomFinding
	for _, f := range findings {
		if severityOrder[f.Severity] >= minLevel {
			filtered = append(filtered, f)
		}
	}
	return filtered
}

func historyCmd() *cobra.Command {
	var clusterName string
	var limit int
	var save bool
	var storeDir string

	cmd := &cobra.Command{
		Use:   "history",
		Short: "View historical scan results",
		Long: `View and manage historical scan results stored locally.

Use --save with other commands (scan, rbac-audit, etc.) to persist results.

Examples:
  idc history
  idc history --cluster my-cluster --limit 10
  idc scan -A --save --cluster-name prod-cluster`,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.NewStore(storeDir)
			if err != nil {
				return fmt.Errorf("failed to initialize store: %w", err)
			}

			scans, err := s.LoadScans(clusterName, limit)
			if err != nil {
				return fmt.Errorf("failed to load scans: %w", err)
			}

			if len(scans) == 0 {
				fmt.Println("No scan history found.")
				fmt.Println("\nTo save scan results, use the --save flag:")
				fmt.Println("  idc scan -A --save --cluster-name my-cluster")
				return nil
			}

			fmt.Printf("=== Scan History ===\n\n")
			fmt.Printf("%-25s %-20s %-10s %-10s %-10s %s\n",
				"TIMESTAMP", "CLUSTER", "FINDINGS", "CRITICAL", "HIGH", "CIS%")
			fmt.Printf("%s\n", strings.Repeat("─", 100))

			for _, scan := range scans {
				cisScore := "-"
				if scan.CISCompliance != nil {
					cisScore = fmt.Sprintf("%.1f%%", scan.CISCompliance.Percentage)
				}
				fmt.Printf("%-25s %-20s %-10d %-10d %-10d %s\n",
					scan.Timestamp.Format("2006-01-02 15:04:05"),
					truncate(scan.ClusterName, 20),
					scan.Summary.TotalFindings,
					scan.Summary.CriticalCount,
					scan.Summary.HighCount,
					cisScore)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&clusterName, "cluster", "", "Filter by cluster name")
	cmd.Flags().IntVar(&limit, "limit", 20, "Maximum number of results")
	cmd.Flags().BoolVar(&save, "save", false, "Save current scan to history")
	cmd.Flags().StringVar(&storeDir, "store-dir", "", "Custom store directory (default: ~/.idc)")

	return cmd
}

func trendCmd() *cobra.Command {
	var clusterName string
	var since string
	var storeDir string

	cmd := &cobra.Command{
		Use:   "trend",
		Short: "Show security posture trends over time",
		Long: `Analyze security posture trends from historical scan data.

Shows how findings and compliance have changed over time.

Examples:
  idc trend --cluster prod-cluster
  idc trend --cluster prod-cluster --since 30d
  idc trend`,
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.NewStore(storeDir)
			if err != nil {
				return fmt.Errorf("failed to initialize store: %w", err)
			}

			duration, err := parseDuration(since)
			if err != nil {
				duration = 30 * 24 * time.Hour
			}

			if clusterName == "" {
				comparisons, err := s.CompareClusters()
				if err != nil {
					return fmt.Errorf("failed to compare clusters: %w", err)
				}

				if len(comparisons) == 0 {
					fmt.Println("No scan data found. Run scans with --save to track trends.")
					return nil
				}

				fmt.Printf("=== Multi-Cluster Comparison ===\n\n")
				fmt.Printf("%-25s %-20s %-10s %-10s %-10s %s\n",
					"CLUSTER", "LAST SCAN", "FINDINGS", "CRITICAL", "HIGH", "CIS%")
				fmt.Printf("%s\n", strings.Repeat("─", 100))

				for _, c := range comparisons {
					cisScore := "-"
					if c.CISCompliance > 0 {
						cisScore = fmt.Sprintf("%.1f%%", c.CISCompliance)
					}
					fmt.Printf("%-25s %-20s %-10d %-10d %-10d %s\n",
						truncate(c.ClusterName, 25),
						c.LastScan.Format("2006-01-02 15:04"),
						c.TotalFindings,
						c.CriticalCount,
						c.HighCount,
						cisScore)
				}
				return nil
			}

			trend, err := s.GetTrend(clusterName, duration)
			if err != nil {
				return fmt.Errorf("failed to get trend data: %w", err)
			}

			if trend == nil || len(trend.DataPoints) == 0 {
				fmt.Printf("No trend data found for cluster: %s\n", clusterName)
				return nil
			}

			fmt.Printf("=== Trend Analysis: %s ===\n\n", clusterName)
			fmt.Printf("Period: %s to %s (%d scans)\n",
				trend.TrendSummary.FirstScan.Format("2006-01-02"),
				trend.TrendSummary.LastScan.Format("2006-01-02"),
				trend.TrendSummary.TotalScans)

			direction := trend.TrendSummary.TrendDirection
			switch direction {
			case "improving":
				fmt.Printf("Trend: IMPROVING (findings reduced by %d)\n", -trend.TrendSummary.FindingsDelta)
			case "degrading":
				fmt.Printf("Trend: DEGRADING (findings increased by %d)\n", trend.TrendSummary.FindingsDelta)
			default:
				fmt.Printf("Trend: STABLE\n")
			}

			if trend.TrendSummary.CriticalDelta != 0 {
				fmt.Printf("Critical Delta: %+d\n", trend.TrendSummary.CriticalDelta)
			}
			if trend.TrendSummary.CISDelta != 0 {
				fmt.Printf("CIS Delta: %+.1f%%\n", trend.TrendSummary.CISDelta)
			}

			fmt.Printf("\nDATA POINTS\n")
			fmt.Printf("%-20s %-10s %-10s %-10s %s\n",
				"DATE", "FINDINGS", "CRITICAL", "HIGH", "CIS%")
			fmt.Printf("%s\n", strings.Repeat("─", 70))

			for _, point := range trend.DataPoints {
				cisScore := "-"
				if point.CISCompliance > 0 {
					cisScore = fmt.Sprintf("%.1f%%", point.CISCompliance)
				}
				fmt.Printf("%-20s %-10d %-10d %-10d %s\n",
					point.Timestamp.Format("2006-01-02 15:04"),
					point.TotalFindings,
					point.CriticalCount,
					point.HighCount,
					cisScore)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&clusterName, "cluster", "", "Cluster name to analyze")
	cmd.Flags().StringVar(&since, "since", "30d", "Time period to analyze (e.g., 7d, 30d)")
	cmd.Flags().StringVar(&storeDir, "store-dir", "", "Custom store directory")

	return cmd
}

func clustersCmd() *cobra.Command {
	var storeDir string

	cmd := &cobra.Command{
		Use:   "clusters",
		Short: "Manage multi-cluster configurations",
		Long: `Configure and manage multiple clusters for aggregated analysis.

Subcommands:
  add     - Add a cluster to the configuration
  list    - List configured clusters
  remove  - Remove a cluster from configuration
  scan    - Scan all configured clusters

Examples:
  idc clusters list
  idc clusters add --name prod --context prod-context
  idc clusters scan -A`,
	}

	listCmd := &cobra.Command{
		Use:   "list",
		Short: "List configured clusters",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.NewStore(storeDir)
			if err != nil {
				return err
			}

			config, err := s.LoadMultiClusterConfig()
			if err != nil {
				return err
			}

			if config == nil || len(config.Clusters) == 0 {
				fmt.Println("No clusters configured.")
				fmt.Println("\nAdd clusters with:")
				fmt.Println("  idc clusters add --name my-cluster --context my-context")
				return nil
			}

			fmt.Printf("=== Configured Clusters ===\n\n")
			fmt.Printf("%-20s %-30s %s\n", "NAME", "CONTEXT", "DESCRIPTION")
			fmt.Printf("%s\n", strings.Repeat("─", 80))

			for _, c := range config.Clusters {
				desc := c.Description
				if len(desc) > 25 {
					desc = desc[:22] + "..."
				}
				fmt.Printf("%-20s %-30s %s\n", c.Name, c.Context, desc)
			}

			return nil
		},
	}

	addCmd := &cobra.Command{
		Use:   "add",
		Short: "Add a cluster to configuration",
		RunE: func(cmd *cobra.Command, args []string) error {
			name, _ := cmd.Flags().GetString("name")
			context, _ := cmd.Flags().GetString("context")
			desc, _ := cmd.Flags().GetString("description")

			if name == "" || context == "" {
				return fmt.Errorf("--name and --context are required")
			}

			s, err := store.NewStore(storeDir)
			if err != nil {
				return err
			}

			config, err := s.LoadMultiClusterConfig()
			if err != nil {
				return err
			}
			if config == nil {
				config = &store.MultiClusterConfig{}
			}

			for _, c := range config.Clusters {
				if c.Name == name {
					return fmt.Errorf("cluster %s already exists", name)
				}
			}

			config.Clusters = append(config.Clusters, store.ClusterConfig{
				Name:        name,
				Context:     context,
				Description: desc,
			})

			if err := s.SaveMultiClusterConfig(config); err != nil {
				return err
			}

			fmt.Printf("Added cluster: %s (context: %s)\n", name, context)
			return nil
		},
	}
	addCmd.Flags().String("name", "", "Cluster name")
	addCmd.Flags().String("context", "", "Kubeconfig context")
	addCmd.Flags().String("description", "", "Optional description")

	removeCmd := &cobra.Command{
		Use:   "remove [name]",
		Short: "Remove a cluster from configuration",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			name := args[0]

			s, err := store.NewStore(storeDir)
			if err != nil {
				return err
			}

			config, err := s.LoadMultiClusterConfig()
			if err != nil {
				return err
			}
			if config == nil {
				return fmt.Errorf("no clusters configured")
			}

			var newClusters []store.ClusterConfig
			found := false
			for _, c := range config.Clusters {
				if c.Name == name {
					found = true
				} else {
					newClusters = append(newClusters, c)
				}
			}

			if !found {
				return fmt.Errorf("cluster %s not found", name)
			}

			config.Clusters = newClusters
			if err := s.SaveMultiClusterConfig(config); err != nil {
				return err
			}

			fmt.Printf("Removed cluster: %s\n", name)
			return nil
		},
	}

	scanAllCmd := &cobra.Command{
		Use:   "scan",
		Short: "Scan all configured clusters",
		RunE: func(cmd *cobra.Command, args []string) error {
			s, err := store.NewStore(storeDir)
			if err != nil {
				return err
			}

			config, err := s.LoadMultiClusterConfig()
			if err != nil {
				return err
			}
			if config == nil || len(config.Clusters) == 0 {
				return fmt.Errorf("no clusters configured")
			}

			fmt.Printf("Scanning %d clusters...\n\n", len(config.Clusters))

			for _, cluster := range config.Clusters {
				fmt.Printf("=== Scanning: %s ===\n", cluster.Name)

				kubecontext = cluster.Context
				if cluster.KubeConfig != "" {
					kubeconfig = cluster.KubeConfig
				}

				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
				g, err := collectGraph(ctx)
				cancel()

				if err != nil {
					fmt.Printf("  Error: %v\n\n", err)
					continue
				}

				rbacResult := analysis.RunRBACAudit(g, analysis.RBACAuditOptions{})
				podSecResult := analysis.RunPodSecurityAudit(g, analysis.PodSecurityOptions{})
				netPolResult := analysis.RunNetworkPolicyAudit(g, analysis.NetworkPolicyOptions{})

				var rbacFindings, podSecFindings, netPolFindings []analysis.RBACFinding
				var podFindings []analysis.PodSecurityFinding
				var netFindings []analysis.NetworkPolicyFinding
				if rbacResult != nil {
					rbacFindings = rbacResult.Findings
				}
				if podSecResult != nil {
					podFindings = podSecResult.Findings
				}
				if netPolResult != nil {
					netFindings = netPolResult.Findings
				}

				cisCompliance := analysis.GenerateCISComplianceSummary(rbacFindings, podFindings, netFindings)

				stats := g.Stats()
				totalFindings := len(rbacFindings) + len(podFindings) + len(netFindings)

				critical, high, medium, low := 0, 0, 0, 0
				for _, f := range rbacFindings {
					switch f.Severity {
					case "critical":
						critical++
					case "high":
						high++
					case "medium":
						medium++
					case "low":
						low++
					}
				}
				for _, f := range podFindings {
					switch f.Severity {
					case "critical":
						critical++
					case "high":
						high++
					case "medium":
						medium++
					case "low":
						low++
					}
				}
				for _, f := range netFindings {
					switch f.Severity {
					case "critical":
						critical++
					case "high":
						high++
					case "medium":
						medium++
					case "low":
						low++
					}
				}

				result := &store.ScanResult{
					Timestamp:    time.Now(),
					ClusterName:  cluster.Name,
					Context:      cluster.Context,
					RBACFindings: len(rbacFindings),
					PodSecFindings: len(podFindings),
					NetPolFindings: len(netFindings),
					Summary: store.ScanSummary{
						TotalWorkloads:       stats.NodeCounts[graph.NodeWorkload],
						TotalServiceAccounts: stats.NodeCounts[graph.NodeServiceAccount],
						TotalRoles:           stats.NodeCounts[graph.NodeRole],
						TotalFindings:        totalFindings,
						CriticalCount:        critical,
						HighCount:            high,
						MediumCount:          medium,
						LowCount:             low,
						FindingsBySeverity: map[string]int{
							"critical": critical,
							"high":     high,
							"medium":   medium,
							"low":      low,
						},
					},
				}

				if cisCompliance != nil {
					result.CISCompliance = &store.CISComplianceScore{
						TotalControls:  cisCompliance.TotalControls,
						PassedControls: cisCompliance.PassedControls,
						FailedControls: cisCompliance.FailedControls,
						Percentage:     float64(cisCompliance.PassedControls) / float64(cisCompliance.TotalControls) * 100,
					}
				}

				if err := s.SaveScan(result); err != nil {
					fmt.Printf("  Warning: Failed to save results: %v\n", err)
				}

				fmt.Printf("  Workloads: %d, SAs: %d, Roles: %d\n",
					result.Summary.TotalWorkloads,
					result.Summary.TotalServiceAccounts,
					result.Summary.TotalRoles)
				fmt.Printf("  Findings: %d (C:%d H:%d M:%d L:%d)\n",
					totalFindings, critical, high, medium, low)
				if result.CISCompliance != nil {
					fmt.Printf("  CIS Compliance: %.1f%%\n", result.CISCompliance.Percentage)
				}
				fmt.Println()
				_ = podSecFindings
				_ = netPolFindings
			}

			fmt.Println("Multi-cluster scan complete. View results with:")
			fmt.Println("  idc trend")
			fmt.Println("  idc history")

			return nil
		},
	}

	cmd.AddCommand(listCmd)
	cmd.AddCommand(addCmd)
	cmd.AddCommand(removeCmd)
	cmd.AddCommand(scanAllCmd)

	cmd.PersistentFlags().StringVar(&storeDir, "store-dir", "", "Custom store directory")

	return cmd
}

func watchCmd() *cobra.Command {
	var metricsAddr string
	var webhookURL string
	var resyncPeriod string
	var debouncePeriod string
	var maxMemoryMB int

	cmd := &cobra.Command{
		Use:   "watch",
		Short: "Continuously watch for identity and RBAC changes",
		Long: `Run as a long-lived process that watches for changes to RBAC,
ServiceAccounts, and workloads. Provides real-time analysis with
Prometheus metrics and webhook notifications.

Deploy as a Kubernetes Deployment for continuous monitoring.

Examples:
  idc watch -A
  idc watch -A --metrics-addr :8080
  idc watch -A --webhook-url https://hooks.slack.com/...
  idc watch -A --resync-period 5m --debounce 30s --max-memory 256`,
		RunE: func(cmd *cobra.Command, args []string) error {
			resync, err := time.ParseDuration(resyncPeriod)
			if err != nil {
				return fmt.Errorf("invalid resync-period: %w", err)
			}

			debounce, err := time.ParseDuration(debouncePeriod)
			if err != nil {
				return fmt.Errorf("invalid debounce: %w", err)
			}

			config := watch.Config{
				Kubeconfig:     kubeconfig,
				Context:        kubecontext,
				AllNamespaces:  allNamespaces,
				Namespace:      namespace,
				IncludeSystem:  includeSystem,
				ResyncPeriod:   resync,
				DebouncePeriod: debounce,
				MaxMemoryMB:    maxMemoryMB,
				MetricsAddr:    metricsAddr,
				WebhookURL:     webhookURL,
			}

			watcher, err := watch.New(config)
			if err != nil {
				return fmt.Errorf("failed to create watcher: %w", err)
			}

			ctx := context.Background()
			return watcher.Run(ctx)
		},
	}

	cmd.Flags().StringVar(&metricsAddr, "metrics-addr", "", "Address for Prometheus metrics endpoint (e.g., :8080)")
	cmd.Flags().StringVar(&webhookURL, "webhook-url", "", "Webhook URL for notifications (JSON or Slack)")
	cmd.Flags().StringVar(&resyncPeriod, "resync-period", "5m", "How often to fully resync with the API server")
	cmd.Flags().StringVar(&debouncePeriod, "debounce", "30s", "Wait time after changes before re-analyzing")
	cmd.Flags().IntVar(&maxMemoryMB, "max-memory", 0, "Maximum memory limit in MB (0 = no limit)")

	return cmd
}
