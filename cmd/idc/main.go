package main

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/api"
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
	rootCmd.AddCommand(sarifCmd())
	rootCmd.AddCommand(diffCmd())
	rootCmd.AddCommand(snapshotCmd())
	rootCmd.AddCommand(openshiftAuditCmd())
	rootCmd.AddCommand(sccSimulateCmd())
	rootCmd.AddCommand(identityRiskCmd())
	rootCmd.AddCommand(complianceCmd())
	rootCmd.AddCommand(chainCmd())
	rootCmd.AddCommand(groupAnalysisCmd())
	rootCmd.AddCommand(usageAnalysisCmd())
	rootCmd.AddCommand(serveCmd())
	rootCmd.AddCommand(smartScanCmd())

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
	var dryRun bool
	var outputFormat string

	cmd := &cobra.Command{
		Use:   "remediate",
		Short: "Generate fix manifests for security findings",
		Long: `Generate Kubernetes manifests to remediate security findings.
Creates YAML that can be applied to fix RBAC, pod security, and network policy issues.

Examples:
  idc remediate -A -f fixes.yaml
  idc remediate -A --severity critical
  idc remediate -A --type rbac -f rbac-fixes.yaml
  idc remediate -A --manifests-only
  idc remediate -A --dry-run -o yaml > fixes.yaml
  idc remediate -A --dry-run -o yaml | kubectl apply --dry-run=client -f -

Dry-run workflow:
  idc remediate -A --dry-run -o yaml > fixes.yaml   # generate patches
  kubectl apply -f fixes.yaml --dry-run=client       # validate
  kubectl apply -f fixes.yaml                        # apply`,
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

			if dryRun || outputFormat == "yaml" {
				yaml := result.GenerateDryRunYAML()
				if yaml == "" {
					fmt.Fprintln(os.Stderr, "No actionable manifests to output.")
					return nil
				}
				fmt.Fprint(out, yaml)
				if outputFile != "" {
					fmt.Fprintf(os.Stderr, "Dry-run manifests saved to: %s\n", outputFile)
					fmt.Fprintf(os.Stderr, "\nTo validate: kubectl apply -f %s --dry-run=client\n", outputFile)
					fmt.Fprintf(os.Stderr, "To apply:    kubectl apply -f %s\n", outputFile)
				}
				return nil
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
	cmd.Flags().BoolVar(&dryRun, "dry-run", false, "Output actionable YAML patches for kubectl apply (skips review-only manifests)")
	cmd.Flags().StringVarP(&outputFormat, "output", "o", "", "Output format: yaml (same as --dry-run)")

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

func sarifCmd() *cobra.Command {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "sarif",
		Short: "Export security findings in SARIF format",
		Long: `Generate a SARIF (Static Analysis Results Interchange Format) report
containing all security findings. SARIF is the standard format for
security tools and integrates with GitHub Security tab.

Examples:
  idc sarif -A -f findings.sarif
  idc sarif -A --include-cloud --aws-region us-west-2 -f findings.sarif`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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

			rbacResult := analysis.RunRBACAudit(g, opts)

			podSecOpts := analysis.PodSecurityOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}
			if allNamespaces {
				podSecOpts.Namespace = ""
			}
			podSecResult := analysis.RunPodSecurityAudit(g, podSecOpts)

			netPolOpts := analysis.NetworkPolicyOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}
			if allNamespaces {
				netPolOpts.Namespace = ""
			}
			netPolResult := analysis.RunNetworkPolicyAudit(g, netPolOpts)

			var cloudResult *analysis.CloudIAMAuditResult
			if includeCloud {
				cloudResult = analysis.AnalyzeCloudIAM(g)
			}

			var w *os.File
			if outputFile != "" {
				var err error
				w, err = os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer w.Close()
			} else {
				w = os.Stdout
			}

			writer := output.NewSARIFWriter(w, "0.3.1")
			return writer.WriteCombinedResults(rbacResult, podSecResult, netPolResult, cloudResult)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Output file path (default: stdout)")

	return cmd
}

func snapshotCmd() *cobra.Command {
	var outputFile string

	cmd := &cobra.Command{
		Use:   "snapshot",
		Short: "Create a snapshot of current security findings",
		Long: `Create a JSON snapshot of all current security findings for later comparison.
Use with 'idc diff' to compare snapshots over time.

Examples:
  idc snapshot -A -f baseline.json
  idc snapshot -A --include-cloud --aws-region us-west-2 -f baseline.json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
			rbacResult := analysis.RunRBACAudit(g, opts)

			podSecOpts := analysis.PodSecurityOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}
			if allNamespaces {
				podSecOpts.Namespace = ""
			}
			podSecResult := analysis.RunPodSecurityAudit(g, podSecOpts)

			netPolOpts := analysis.NetworkPolicyOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}
			if allNamespaces {
				netPolOpts.Namespace = ""
			}
			netPolResult := analysis.RunNetworkPolicyAudit(g, netPolOpts)

			var cloudFindings []analysis.CloudIAMFinding
			if includeCloud {
				cloudResult := analysis.AnalyzeCloudIAM(g)
				cloudFindings = cloudResult.Findings
			}

			snapshot := struct {
				Timestamp       string                          `json:"timestamp"`
				RBACFindings    []analysis.RBACFinding          `json:"rbac_findings"`
				PodSecFindings  []analysis.PodSecurityFinding   `json:"pod_security_findings"`
				NetPolFindings  []analysis.NetworkPolicyFinding `json:"network_policy_findings"`
				CloudFindings   []analysis.CloudIAMFinding      `json:"cloud_findings"`
			}{
				Timestamp:      time.Now().UTC().Format(time.RFC3339),
				RBACFindings:   rbacResult.Findings,
				PodSecFindings: podSecResult.Findings,
				NetPolFindings: netPolResult.Findings,
				CloudFindings:  cloudFindings,
			}

			var w *os.File
			if outputFile != "" {
				var err error
				w, err = os.Create(outputFile)
				if err != nil {
					return fmt.Errorf("failed to create output file: %w", err)
				}
				defer w.Close()
			} else {
				w = os.Stdout
			}

			encoder := json.NewEncoder(w)
			encoder.SetIndent("", "  ")
			return encoder.Encode(snapshot)
		},
	}

	cmd.Flags().StringVarP(&outputFile, "output-file", "f", "", "Output file path (default: stdout)")

	return cmd
}

func diffCmd() *cobra.Command {
	var baselineFile string

	cmd := &cobra.Command{
		Use:   "diff",
		Short: "Compare current findings against a baseline snapshot",
		Long: `Compare the current security state against a previously saved baseline.
Shows new findings, resolved findings, and overall trend.

Examples:
  idc diff -A --baseline baseline.json
  idc diff -A --baseline before.json -o json`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if baselineFile == "" {
				return fmt.Errorf("--baseline is required")
			}

			baselineData, err := os.ReadFile(baselineFile)
			if err != nil {
				return fmt.Errorf("failed to read baseline file: %w", err)
			}

			var baseline struct {
				RBACFindings   []analysis.RBACFinding          `json:"rbac_findings"`
				PodSecFindings []analysis.PodSecurityFinding   `json:"pod_security_findings"`
				NetPolFindings []analysis.NetworkPolicyFinding `json:"network_policy_findings"`
				CloudFindings  []analysis.CloudIAMFinding      `json:"cloud_findings"`
			}
			if err := json.Unmarshal(baselineData, &baseline); err != nil {
				return fmt.Errorf("failed to parse baseline: %w", err)
			}

			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
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
			rbacResult := analysis.RunRBACAudit(g, opts)

			podSecOpts := analysis.PodSecurityOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}
			if allNamespaces {
				podSecOpts.Namespace = ""
			}
			podSecResult := analysis.RunPodSecurityAudit(g, podSecOpts)

			netPolOpts := analysis.NetworkPolicyOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}
			if allNamespaces {
				netPolOpts.Namespace = ""
			}
			netPolResult := analysis.RunNetworkPolicyAudit(g, netPolOpts)

			var cloudFindings []analysis.CloudIAMFinding
			if includeCloud {
				cloudResult := analysis.AnalyzeCloudIAM(g)
				cloudFindings = cloudResult.Findings
			}

			baselineFindings := &analysis.ScanFindings{
				RBACFindings:   baseline.RBACFindings,
				PodSecFindings: baseline.PodSecFindings,
				NetPolFindings: baseline.NetPolFindings,
				CloudFindings:  baseline.CloudFindings,
			}

			currentFindings := &analysis.ScanFindings{
				RBACFindings:   rbacResult.Findings,
				PodSecFindings: podSecResult.Findings,
				NetPolFindings: netPolResult.Findings,
				CloudFindings:  cloudFindings,
			}

			result := analysis.ComputeDiff(baselineFindings, currentFindings)

			if outputFormat == "json" {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			fmt.Printf("Security Posture Comparison\n")
			fmt.Printf("===========================\n\n")
			fmt.Printf("Status: %s\n\n", strings.ToUpper(result.Summary.Status))
			fmt.Printf("Baseline: %d findings\n", result.Summary.BaselineTotal)
			fmt.Printf("Current:  %d findings\n\n", result.Summary.CurrentTotal)

			if len(result.NewFindings) > 0 {
				fmt.Printf("NEW FINDINGS (%d):\n", len(result.NewFindings))
				fmt.Printf("-----------------\n")
				for _, f := range result.NewFindings {
					fmt.Printf("  [%s] %s - %s\n", f.Severity, f.CheckID, f.Title)
					if f.Namespace != "" {
						fmt.Printf("         Namespace: %s, Resource: %s\n", f.Namespace, f.Resource)
					} else if f.Resource != "" {
						fmt.Printf("         Resource: %s\n", f.Resource)
					}
				}
				fmt.Println()
			}

			if len(result.ResolvedFindings) > 0 {
				fmt.Printf("RESOLVED FINDINGS (%d):\n", len(result.ResolvedFindings))
				fmt.Printf("----------------------\n")
				for _, f := range result.ResolvedFindings {
					fmt.Printf("  [%s] %s - %s\n", f.Severity, f.CheckID, f.Title)
					if f.Namespace != "" {
						fmt.Printf("         Namespace: %s, Resource: %s\n", f.Namespace, f.Resource)
					} else if f.Resource != "" {
						fmt.Printf("         Resource: %s\n", f.Resource)
					}
				}
				fmt.Println()
			}

			fmt.Printf("Unchanged: %d findings\n", result.UnchangedCount)

			return nil
		},
	}

	cmd.Flags().StringVar(&baselineFile, "baseline", "", "Baseline snapshot file to compare against (required)")

	return cmd
}

func openshiftAuditCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "openshift-audit",
		Short: "Comprehensive OpenShift security audit",
		Long: `Run a comprehensive security audit specific to OpenShift clusters.
Analyzes SCCs, Routes, OAuth clients, BuildConfigs, Projects, and OpenShift RBAC.

This command only works on OpenShift clusters. On vanilla Kubernetes
clusters, it will report that OpenShift is not detected.

Examples:
  idc openshift-audit -A
  idc openshift-audit -A --include-system
  idc openshift-audit -n myproject`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.OpenShiftAuditOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
			}
			if allNamespaces {
				opts.Namespace = ""
			}

			result := analysis.RunOpenShiftAudit(g, opts)

			if !result.IsOpenShift {
				fmt.Println("OpenShift not detected. This command is for OpenShift clusters only.")
				fmt.Println("Use 'idc rbac-audit' for standard Kubernetes RBAC analysis.")
				return nil
			}

			if outputFormat == "json" {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			fmt.Println("OpenShift Security Audit")
			fmt.Println("========================")
			fmt.Println()

			fmt.Printf("Summary:\n")
			fmt.Printf("  Total Findings:    %d\n", result.Summary.TotalFindings)
			fmt.Printf("  Critical:          %d\n", result.Summary.CriticalFindings)
			fmt.Printf("  High:              %d\n", result.Summary.HighFindings)
			fmt.Printf("  Medium:            %d\n", result.Summary.MediumFindings)
			fmt.Printf("  Low:               %d\n\n", result.Summary.LowFindings)

			if result.SCCAnalysis != nil && len(result.SCCAnalysis.RiskyBindings) > 0 {
				fmt.Printf("SCC Analysis:\n")
				fmt.Printf("  Total SCCs:        %d\n", result.SCCAnalysis.Summary.TotalSCCs)
				fmt.Printf("  Privileged SCCs:   %d\n", result.SCCAnalysis.Summary.PrivilegedSCCs)
				fmt.Printf("  Risky Bindings:    %d\n", result.SCCAnalysis.Summary.RiskyBindings)
				fmt.Printf("  Escalation Paths:  %d\n\n", result.SCCAnalysis.Summary.EscalationPaths)
			}

			printOpenShiftFindings("Route Findings", result.RouteFindings)
			printOpenShiftFindings("OAuth Findings", result.OAuthFindings)
			printOpenShiftFindings("Build Findings", result.BuildFindings)
			printOpenShiftFindings("Project Findings", result.ProjectFindings)
			printOpenShiftFindings("RBAC Findings", result.RBACFindings)

			if result.SCCAnalysis != nil && len(result.SCCAnalysis.RiskyBindings) > 0 {
				fmt.Printf("\nRisky SCC Bindings:\n")
				fmt.Printf("-------------------\n")
				for _, b := range result.SCCAnalysis.RiskyBindings {
					fmt.Printf("  [%s] %s -> %s\n", strings.ToUpper(b.RiskLevel), b.SubjectName, b.SCCName)
					if b.SubjectNS != "" {
						fmt.Printf("         Namespace: %s\n", b.SubjectNS)
					}
					fmt.Printf("         Reason: %s\n", b.RiskReason)
				}
			}

			if result.SCCAnalysis != nil && len(result.SCCAnalysis.EscalationPaths) > 0 {
				fmt.Printf("\nSCC Escalation Paths:\n")
				fmt.Printf("--------------------\n")
				for _, p := range result.SCCAnalysis.EscalationPaths {
					fmt.Printf("  [%s] %s -> %s (via %s)\n", strings.ToUpper(p.RiskLevel), p.Source, p.TargetSCC, p.Via)
				}
			}

			return nil
		},
	}

	return cmd
}

func printOpenShiftFindings(title string, findings []analysis.OpenShiftFinding) {
	if len(findings) == 0 {
		return
	}

	fmt.Printf("\n%s:\n", title)
	fmt.Println(strings.Repeat("-", len(title)+1))

	for _, f := range findings {
		fmt.Printf("  [%s] %s: %s\n", strings.ToUpper(string(f.Severity)), f.CheckID, f.Title)
		fmt.Printf("         %s\n", f.Description)
		if len(f.Affected) > 0 && len(f.Affected) <= 5 {
			for _, a := range f.Affected {
				if a.Namespace != "" {
					fmt.Printf("         - %s/%s\n", a.Namespace, a.Name)
				} else {
					fmt.Printf("         - %s\n", a.Name)
				}
			}
		} else if len(f.Affected) > 5 {
			for _, a := range f.Affected[:3] {
				if a.Namespace != "" {
					fmt.Printf("         - %s/%s\n", a.Namespace, a.Name)
				} else {
					fmt.Printf("         - %s\n", a.Name)
				}
			}
			fmt.Printf("         ... and %d more\n", len(f.Affected)-3)
		}
	}
}

func sccSimulateCmd() *cobra.Command {
	var workload string

	cmd := &cobra.Command{
		Use:   "scc-simulate",
		Short: "Simulate which SCC a workload would use",
		Long: `Determine which Security Context Constraint would be selected
for a specific workload based on its service account and security context.

This helps understand the effective security constraints for workloads.

Examples:
  idc scc-simulate --workload deployment/myapp -n myproject
  idc scc-simulate --workload pod/mypod -n myproject`,
		RunE: func(cmd *cobra.Command, args []string) error {
			if workload == "" {
				return fmt.Errorf("--workload is required")
			}

			ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			sccs := g.GetNodesByType(graph.NodeSCC)
			if len(sccs) == 0 {
				fmt.Println("No SCCs found. This command is for OpenShift clusters only.")
				return nil
			}

			nodeID := resolveWorkloadNodeID(g, workload, namespace)
			workloadNode := g.GetNode(nodeID)
			if workloadNode == nil {
				return fmt.Errorf("workload not found: %s", workload)
			}

			saEdges := g.GetOutEdges(workloadNode.ID)
			var saNode *graph.Node
			for _, edge := range saEdges {
				if edge.Type == graph.EdgeUses {
					saNode = g.GetNode(edge.To)
					break
				}
			}

			if saNode == nil {
				fmt.Println("No ServiceAccount found for workload")
				return nil
			}

			sccResult := analysis.AnalyzeSCCs(g)

			saRef := "system:serviceaccount:" + saNode.Namespace + ":" + saNode.Name

			fmt.Printf("Workload: %s/%s\n", workloadNode.Namespace, workloadNode.Name)
			fmt.Printf("ServiceAccount: %s/%s\n\n", saNode.Namespace, saNode.Name)

			var matchingBindings []analysis.SCCBinding
			for _, binding := range sccResult.SCCBindings {
				if binding.SubjectType == "ServiceAccount" &&
					binding.SubjectNS == saNode.Namespace &&
					binding.SubjectName == saNode.Name {
					matchingBindings = append(matchingBindings, binding)
				}
				if binding.SubjectType == "User" && binding.SubjectName == saRef {
					matchingBindings = append(matchingBindings, binding)
				}
				if binding.SubjectType == "Group" {
					if binding.SubjectName == "system:serviceaccounts" ||
						binding.SubjectName == "system:serviceaccounts:"+saNode.Namespace ||
						binding.SubjectName == "system:authenticated" {
						matchingBindings = append(matchingBindings, binding)
					}
				}
			}

			if len(matchingBindings) == 0 {
				fmt.Println("No SCC bindings found for this ServiceAccount")
				fmt.Println("The workload would use the 'restricted' SCC by default")
				return nil
			}

			fmt.Println("Available SCCs for this ServiceAccount:")
			fmt.Println("----------------------------------------")

			type sccWithPriority struct {
				name     string
				priority int
				access   []string
			}

			sccMap := make(map[string]*sccWithPriority)
			for _, binding := range matchingBindings {
				if _, exists := sccMap[binding.SCCName]; !exists {
					sccDetail := sccResult.GetSCCByName(binding.SCCName)
					if sccDetail != nil {
						sccMap[binding.SCCName] = &sccWithPriority{
							name:     binding.SCCName,
							priority: sccDetail.Priority,
							access:   sccDetail.AllowedFlags,
						}
					}
				}
			}

			var sccList []*sccWithPriority
			for _, scc := range sccMap {
				sccList = append(sccList, scc)
			}

			for i := 0; i < len(sccList)-1; i++ {
				for j := i + 1; j < len(sccList); j++ {
					if sccList[j].priority > sccList[i].priority {
						sccList[i], sccList[j] = sccList[j], sccList[i]
					}
				}
			}

			for i, scc := range sccList {
				marker := "  "
				if i == 0 {
					marker = "* "
				}
				fmt.Printf("%s[Priority %d] %s\n", marker, scc.priority, scc.name)
				if len(scc.access) > 0 {
					fmt.Printf("    Allows: %s\n", strings.Join(scc.access, ", "))
				}
			}

			if len(sccList) > 0 {
				fmt.Printf("\n* = Selected SCC (highest priority)\n")

				sccDetail := sccResult.GetSCCByName(sccList[0].name)
				if sccDetail != nil && sccDetail.RiskLevel != "low" {
					fmt.Printf("\nWARNING: Selected SCC '%s' has %s risk level\n", sccList[0].name, sccDetail.RiskLevel)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&workload, "workload", "", "Workload reference (e.g., deployment/myapp, pod/mypod)")

	return cmd
}

func identityRiskCmd() *cobra.Command {
	var minScore int
	var topN int

	cmd := &cobra.Command{
		Use:   "identity-risk",
		Short: "Calculate risk scores for all identities",
		Long: `Calculate a comprehensive risk score for each service account based on:
- Kubernetes RBAC permissions
- Cloud IAM permissions (AWS/GCP/Azure)
- OpenShift SCC access
- Workload blast radius

The risk score helps identify overprivileged identities that should be reviewed.

Examples:
  idc identity-risk -A
  idc identity-risk -A --top 20
  idc identity-risk -A --min-score 50
  idc identity-risk -A --include-cloud --aws-region us-west-2`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.IdentityRiskOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
				MinScore:      minScore,
				TopN:          topN,
			}
			if allNamespaces {
				opts.Namespace = ""
			}

			result := analysis.CalculateIdentityRisk(g, opts)

			if outputFormat == "json" {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			fmt.Println("Identity Risk Assessment")
			fmt.Println("========================")
			fmt.Println()

			fmt.Printf("Summary:\n")
			fmt.Printf("  Total Identities:     %d\n", result.Summary.TotalIdentities)
			fmt.Printf("  Critical Risk:        %d\n", result.Summary.CriticalRiskCount)
			fmt.Printf("  High Risk:            %d\n", result.Summary.HighRiskCount)
			fmt.Printf("  Medium Risk:          %d\n", result.Summary.MediumRiskCount)
			fmt.Printf("  Low Risk:             %d\n", result.Summary.LowRiskCount)
			fmt.Printf("  With Cloud Access:    %d\n", result.Summary.WithCloudAccess)
			fmt.Printf("  With Cluster-Admin:   %d\n", result.Summary.WithClusterAdmin)
			fmt.Printf("  With Secrets Access:  %d\n", result.Summary.WithSecretsAccess)
			fmt.Printf("  Overprivileged:       %d\n", result.Summary.OverprivilegedCount)
			fmt.Printf("  Average Score:        %d\n\n", result.Summary.AverageScore)

			if len(result.TopRisks) > 0 {
				fmt.Printf("Top %d Risky Identities:\n", len(result.TopRisks))
				fmt.Println(strings.Repeat("-", 80))
				fmt.Printf("%-40s %-10s %-6s %s\n", "IDENTITY", "NAMESPACE", "SCORE", "RISK")
				fmt.Println(strings.Repeat("-", 80))

				for _, id := range result.TopRisks {
					name := id.Name
					if len(name) > 38 {
						name = name[:35] + "..."
					}
					ns := id.Namespace
					if len(ns) > 8 {
						ns = ns[:8]
					}
					fmt.Printf("%-40s %-10s %-6d %s\n", name, ns, id.RiskScore, strings.ToUpper(id.RiskLevel))

					if len(id.RiskFactors) > 0 {
						factorCount := len(id.RiskFactors)
						if factorCount > 3 {
							factorCount = 3
						}
						for i := 0; i < factorCount; i++ {
							f := id.RiskFactors[i]
							fmt.Printf("  └─ [%s] %s (+%d)\n", strings.ToUpper(string(f.Severity)), f.Description, f.Score)
						}
						if len(id.RiskFactors) > 3 {
							fmt.Printf("  └─ ... and %d more factors\n", len(id.RiskFactors)-3)
						}
					}
				}
			}

			if len(result.Recommendations) > 0 {
				fmt.Printf("\nRecommendations:\n")
				fmt.Println(strings.Repeat("-", 40))
				for i, rec := range result.Recommendations {
					fmt.Printf("%d. %s\n", i+1, rec)
				}
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&minScore, "min-score", 0, "Only show identities with score >= this value")
	cmd.Flags().IntVar(&topN, "top", 10, "Show top N risky identities")

	return cmd
}

func complianceCmd() *cobra.Command {
	var frameworks string

	cmd := &cobra.Command{
		Use:   "compliance",
		Short: "Run compliance framework analysis",
		Long: `Map security findings to compliance frameworks and calculate compliance scores.

Supported frameworks:
  - CIS Kubernetes Benchmark v1.8
  - NSA/CISA Kubernetes Hardening Guide
  - NIST 800-53 (Identity Controls)
  - SOC2 (Identity Requirements)
  - PCI-DSS (Service Account Controls)

The analysis maps RBAC, pod security, and platform findings to specific controls
in each framework and calculates per-section and overall compliance percentages.

Examples:
  idc compliance -A
  idc compliance -A --frameworks CIS,NIST
  idc compliance -A -o json > compliance-report.json
  idc compliance -n prod --frameworks SOC2,PCIDSS`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.ComplianceOptions{
				IncludeSystem: includeSystem,
				Namespace:     namespace,
				IncludeCloud:  includeCloud,
			}
			if allNamespaces {
				opts.Namespace = ""
			}

			if frameworks != "" {
				fwList := strings.Split(frameworks, ",")
				for _, fw := range fwList {
					switch strings.ToUpper(strings.TrimSpace(fw)) {
					case "CIS":
						opts.Frameworks = append(opts.Frameworks, analysis.FrameworkCIS)
					case "NSA", "NSA_CISA", "NSACISA":
						opts.Frameworks = append(opts.Frameworks, analysis.FrameworkNSACISA)
					case "NIST", "NIST800-53":
						opts.Frameworks = append(opts.Frameworks, analysis.FrameworkNIST)
					case "SOC2":
						opts.Frameworks = append(opts.Frameworks, analysis.FrameworkSOC2)
					case "PCIDSS", "PCI-DSS", "PCI":
						opts.Frameworks = append(opts.Frameworks, analysis.FrameworkPCIDSS)
					}
				}
			}

			result := analysis.RunComplianceAnalysis(g, opts)

			if outputFormat == "json" {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			fmt.Println("Compliance Framework Analysis")
			fmt.Println("==============================")
			fmt.Println()

			fmt.Printf("Overall Compliance Score: %.1f%%\n", result.OverallScore)
			fmt.Printf("Total Findings Mapped: %d\n", result.Summary.TotalFindings)
			fmt.Printf("Critical Gaps: %d\n", result.Summary.CriticalGapsCount)
			fmt.Printf("High Gaps: %d\n\n", result.Summary.HighGapsCount)

			for _, fc := range result.Frameworks {
				fmt.Printf("%s (%s)\n", fc.Name, fc.Version)
				fmt.Println(strings.Repeat("-", 60))
				fmt.Printf("  Compliance: %.1f%% (%d/%d controls passed)\n",
					fc.CompliancePercent, fc.PassedControls, fc.TotalControls)

				if len(fc.SectionResults) > 0 {
					fmt.Println("  Sections:")
					for _, sec := range fc.SectionResults {
						if sec.TotalControls > 0 {
							status := "✓"
							if sec.FailedControls > 0 {
								status = "✗"
							}
							fmt.Printf("    %s %s: %.1f%% (%d/%d)\n",
								status, sec.SectionTitle, sec.CompliancePercent,
								sec.PassedControls, sec.TotalControls)
						}
					}
				}

				if len(fc.TopGaps) > 0 {
					fmt.Println("  Top Gaps:")
					for i, gap := range fc.TopGaps {
						if i >= 5 {
							break
						}
						fmt.Printf("    [%s] %s: %s\n",
							strings.ToUpper(string(gap.Severity)),
							gap.ControlID,
							gap.ControlTitle)
					}
				}
				fmt.Println()
			}

			if len(result.Recommendations) > 0 {
				fmt.Println("Recommendations:")
				for _, rec := range result.Recommendations {
					fmt.Printf("  • %s\n", rec)
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&frameworks, "frameworks", "", "Comma-separated list of frameworks (CIS,NSA_CISA,NIST,SOC2,PCIDSS)")

	return cmd
}

func chainCmd() *cobra.Command {
	var workload string
	var format string

	cmd := &cobra.Command{
		Use:   "chain",
		Short: "Trace identity chains from workloads to cloud resources",
		Long: `Analyze the complete identity chain from workloads through service accounts,
RBAC roles, and cloud IAM roles to cloud resources.

This command provides full visibility into:
- Pod → ServiceAccount → Role/ClusterRole chains
- ServiceAccount → AWS IAM Role (IRSA/Pod Identity) chains
- ServiceAccount → GCP Workload Identity chains
- ServiceAccount → Azure Managed Identity chains
- Cross-account role assumption chains
- Trust relationships
- Effective permissions calculation

Output formats:
- json (default): Full JSON output
- dot: Graphviz DOT format for visualization
- mermaid: Mermaid diagram format

Examples:
  idc chain -A
  idc chain --workload deployment/api-server -n prod
  idc chain -A --format dot > chain.dot
  idc chain -A --format mermaid
  idc chain -A -o json | jq '.high_risk_chains'`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.IdentityChainOptions{
				Namespace:    namespace,
				WorkloadRef:  workload,
				IncludeCloud: includeCloud,
				MaxDepth:     10,
			}
			if allNamespaces {
				opts.Namespace = ""
			}

			if format == "dot" || format == "mermaid" || format == "all" {
				opts.OutputFormat = format
			}

			result := analysis.AnalyzeIdentityChains(g, opts)

			if format == "dot" && result.DOTOutput != "" {
				fmt.Print(result.DOTOutput)
				return nil
			}
			if format == "mermaid" && result.MermaidOutput != "" {
				fmt.Print(result.MermaidOutput)
				return nil
			}

			if outputFormat == "json" {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			fmt.Println("Identity Chain Analysis")
			fmt.Println("=======================")
			fmt.Println()

			fmt.Printf("Summary:\n")
			fmt.Printf("  Total Chains:          %d\n", result.Summary.TotalChains)
			fmt.Printf("  With Cloud Access:     %d\n", result.Summary.ChainsWithCloudAccess)
			fmt.Printf("  Cross-Account:         %d\n", result.Summary.CrossAccountChains)
			fmt.Printf("  With Admin:            %d\n", result.Summary.ChainsWithAdmin)
			fmt.Printf("  Avg Chain Depth:       %.1f\n", result.Summary.AverageChainDepth)
			fmt.Printf("  Max Chain Depth:       %d\n", result.Summary.MaxChainDepth)
			fmt.Println()

			if len(result.Summary.ByCloudProvider) > 0 {
				fmt.Println("By Cloud Provider:")
				for provider, count := range result.Summary.ByCloudProvider {
					fmt.Printf("  %-10s %d\n", provider, count)
				}
				fmt.Println()
			}

			fmt.Println("By Risk Level:")
			for level, count := range result.Summary.ByRiskLevel {
				fmt.Printf("  %-10s %d\n", strings.ToUpper(level), count)
			}
			fmt.Println()

			if len(result.HighRiskChains) > 0 {
				fmt.Printf("High Risk Chains (%d):\n", len(result.HighRiskChains))
				fmt.Println(strings.Repeat("-", 80))
				fmt.Printf("%-35s %-15s %-8s %-6s %s\n", "WORKLOAD", "NAMESPACE", "SCORE", "CLOUD", "CROSS-ACCT")
				fmt.Println(strings.Repeat("-", 80))

				for _, chain := range result.HighRiskChains {
					name := chain.WorkloadName
					if len(name) > 33 {
						name = name[:30] + "..."
					}
					ns := chain.WorkloadNamespace
					if len(ns) > 13 {
						ns = ns[:13]
					}
					cloudAccess := "No"
					if chain.HasCloudAccess {
						cloudAccess = "Yes"
					}
					crossAccount := "No"
					if chain.IsCrossAccount {
						crossAccount = "Yes"
					}
					fmt.Printf("%-35s %-15s %-8d %-6s %s\n",
						name, ns, chain.RiskScore, cloudAccess, crossAccount)
				}
				fmt.Println()
			}

			if len(result.Chains) > 0 && workload != "" {
				chain := result.Chains[0]
				fmt.Printf("\nChain Details for %s:\n", workload)
				fmt.Println(strings.Repeat("-", 60))

				if chain.ServiceAccount != nil {
					fmt.Printf("  ServiceAccount: %s/%s\n", chain.ServiceAccount.Namespace, chain.ServiceAccount.Name)
					if chain.ServiceAccount.CloudProvider != "" {
						fmt.Printf("  Cloud Provider: %s\n", chain.ServiceAccount.CloudProvider)
					}
					if chain.ServiceAccount.CloudRoleARN != "" {
						fmt.Printf("  AWS Role ARN:   %s\n", chain.ServiceAccount.CloudRoleARN)
					}
					if chain.ServiceAccount.GCPServiceAccount != "" {
						fmt.Printf("  GCP SA:         %s\n", chain.ServiceAccount.GCPServiceAccount)
					}
				}

				if len(chain.K8sRoles) > 0 {
					fmt.Println("\n  K8s Roles:")
					for _, role := range chain.K8sRoles {
						roleType := "Role"
						if role.IsClusterRole {
							roleType = "ClusterRole"
						}
						fmt.Printf("    - %s: %s (via %s)\n", roleType, role.Name, role.ViaBinding)
					}
				}

				if len(chain.CloudRoles) > 0 {
					fmt.Println("\n  Cloud Roles:")
					for _, role := range chain.CloudRoles {
						adminStr := ""
						if role.IsAdmin {
							adminStr = " [ADMIN]"
						}
						fmt.Printf("    - %s: %s%s\n", role.Provider, role.RoleName, adminStr)
					}
				}

				if chain.EffectivePermissions != nil {
					fmt.Println("\n  Effective Permissions:")
					if chain.EffectivePermissions.HasClusterAdmin {
						fmt.Println("    [!] Has Cluster Admin")
					}
					if chain.EffectivePermissions.HasCloudAdmin {
						fmt.Println("    [!] Has Cloud Admin")
					}
					if chain.EffectivePermissions.CanAccessSecrets {
						fmt.Println("    [!] Can Access Secrets")
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().StringVarP(&workload, "workload", "w", "", "Specific workload to trace (e.g., deployment/api-server)")
	cmd.Flags().StringVar(&format, "format", "", "Output format: dot, mermaid, or all")

	return cmd
}

func groupAnalysisCmd() *cobra.Command {
	cmd := &cobra.Command{
		Use:   "group-analysis",
		Short: "Analyze group permissions and nested access",
		Long: `Analyze RBAC group permissions, OIDC/LDAP group mappings, nested
permission paths, and privilege escalation vectors through groups.

This command identifies:
- High-risk groups with cluster-admin or secrets access
- OIDC group to K8s group mappings and their effective permissions
- Privilege escalation paths through groups (escalate, bind, impersonate verbs)
- Nested permission inheritance
- Built-in system group bindings (system:authenticated, system:masters, etc.)

Examples:
  idc group-analysis -A
  idc group-analysis -A -o json
  idc group-analysis -A --include-system`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.GroupAnalysisOptions{
				Namespace:     namespace,
				IncludeSystem: includeSystem,
			}
			if allNamespaces {
				opts.Namespace = ""
			}

			result := analysis.AnalyzeGroups(g, opts)

			if outputFormat == "json" {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			fmt.Println("Group Permission Analysis")
			fmt.Println("=========================")
			fmt.Println()

			fmt.Printf("Summary:\n")
			fmt.Printf("  Total Groups:        %d\n", result.Summary.TotalGroups)
			fmt.Printf("  High Risk Groups:    %d\n", result.Summary.HighRiskGroups)
			fmt.Printf("  Groups with Admin:   %d\n", result.Summary.GroupsWithAdmin)
			fmt.Printf("  Groups with Secrets: %d\n", result.Summary.GroupsWithSecrets)
			fmt.Printf("  OIDC Mappings:       %d\n", result.Summary.OIDCMappings)
			fmt.Printf("  Priv Esc Paths:      %d\n", result.Summary.PrivEscPaths)
			fmt.Println()

			if len(result.Summary.ByGroupType) > 0 {
				fmt.Println("By Group Type:")
				for gtype, count := range result.Summary.ByGroupType {
					fmt.Printf("  %-10s %d\n", gtype, count)
				}
				fmt.Println()
			}

			if len(result.HighRiskGroups) > 0 {
				fmt.Printf("High Risk Groups (%d):\n", len(result.HighRiskGroups))
				fmt.Println(strings.Repeat("-", 80))
				fmt.Printf("%-40s %-10s %-8s %-6s %s\n", "GROUP", "TYPE", "SCORE", "ADMIN", "SECRETS")
				fmt.Println(strings.Repeat("-", 80))

				for _, group := range result.HighRiskGroups {
					name := group.Name
					if len(name) > 38 {
						name = name[:35] + "..."
					}
					admin := "No"
					if group.HasClusterAdmin {
						admin = "Yes"
					}
					secrets := "No"
					if group.HasSecretsAccess {
						secrets = "Yes"
					}
					fmt.Printf("%-40s %-10s %-8d %-6s %s\n",
						name, group.Type, group.RiskScore, admin, secrets)
				}
				fmt.Println()
			}

			if len(result.PrivilegeEscalation) > 0 {
				fmt.Printf("Privilege Escalation Paths (%d):\n", len(result.PrivilegeEscalation))
				fmt.Println(strings.Repeat("-", 80))
				for _, path := range result.PrivilegeEscalation {
					fmt.Printf("  [%s] %s\n", strings.ToUpper(path.Severity), path.Group)
					fmt.Printf("    Technique: %s\n", path.Technique)
					fmt.Printf("    Path: %s\n", strings.Join(path.EscalationPath, " -> "))
				}
				fmt.Println()
			}

			if len(result.OIDCGroupMappings) > 0 {
				fmt.Printf("OIDC Group Mappings (%d):\n", len(result.OIDCGroupMappings))
				fmt.Println(strings.Repeat("-", 60))
				for _, mapping := range result.OIDCGroupMappings {
					fmt.Printf("  %s -> %s [%s]\n",
						mapping.OIDCGroup, mapping.K8sGroup, mapping.RiskLevel)
					if len(mapping.EffectiveRoles) > 0 {
						fmt.Printf("    Roles: %s\n", strings.Join(mapping.EffectiveRoles, ", "))
					}
				}
				fmt.Println()
			}

			if len(result.Recommendations) > 0 {
				fmt.Println("Recommendations:")
				for _, rec := range result.Recommendations {
					fmt.Printf("  • %s\n", rec)
				}
			}

			return nil
		},
	}

	return cmd
}

func usageAnalysisCmd() *cobra.Command {
	var staleDays int

	cmd := &cobra.Command{
		Use:   "usage-analysis",
		Short: "Analyze identity usage and over-provisioning",
		Long: `Detect unused service accounts, orphaned identities, over-provisioned
accounts, and stale identities. Provides right-sizing recommendations.

This command identifies:
- Unused service accounts (no workloads attached)
- Orphaned identities (have bindings but no active usage)
- Over-provisioned accounts (more permissions than needed)
- Stale identities (not used within threshold days)
- Right-sizing recommendations to reduce attack surface

Examples:
  idc usage-analysis -A
  idc usage-analysis -A --stale-days 60
  idc usage-analysis -A -o json
  idc usage-analysis -n prod --include-system`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 3*time.Minute)
			defer cancel()

			g, err := collectGraph(ctx)
			if err != nil {
				return fmt.Errorf("failed to collect cluster data: %w", err)
			}

			opts := analysis.UsageAnalysisOptions{
				Namespace:     namespace,
				IncludeSystem: includeSystem,
				StaleDays:     staleDays,
			}
			if allNamespaces {
				opts.Namespace = ""
			}

			result := analysis.AnalyzeUsage(g, opts)

			if outputFormat == "json" {
				encoder := json.NewEncoder(os.Stdout)
				encoder.SetIndent("", "  ")
				return encoder.Encode(result)
			}

			fmt.Println("Identity Usage Analysis")
			fmt.Println("=======================")
			fmt.Println()

			fmt.Printf("Summary:\n")
			fmt.Printf("  Total Service Accounts:  %d\n", result.Summary.TotalServiceAccounts)
			fmt.Printf("  Unused:                  %d\n", result.Summary.UnusedCount)
			fmt.Printf("  Orphaned:                %d\n", result.Summary.OrphanedCount)
			fmt.Printf("  Over-Provisioned:        %d\n", result.Summary.OverProvisionedCount)
			fmt.Printf("  High Risk Unused:        %d\n", result.Summary.HighRiskUnused)
			fmt.Printf("  Right-Sizing Recs:       %d\n", result.Summary.TotalRightSizingRecs)
			if result.Summary.AvgOverProvisionRate > 0 {
				fmt.Printf("  Avg Over-Provision:      %.0f%%\n", result.Summary.AvgOverProvisionRate*100)
			}
			fmt.Println()

			if len(result.UnusedServiceAccounts) > 0 {
				fmt.Printf("Unused Service Accounts (%d):\n", len(result.UnusedServiceAccounts))
				fmt.Println(strings.Repeat("-", 80))
				fmt.Printf("%-35s %-15s %-10s %-10s %s\n", "NAME", "NAMESPACE", "BINDINGS", "CLOUD", "RISK")
				fmt.Println(strings.Repeat("-", 80))

				for _, sa := range result.UnusedServiceAccounts {
					name := sa.Name
					if len(name) > 33 {
						name = name[:30] + "..."
					}
					ns := sa.Namespace
					if len(ns) > 13 {
						ns = ns[:13]
					}
					bindings := "No"
					if sa.HasRoleBindings {
						bindings = "Yes"
					}
					cloud := "No"
					if sa.HasCloudRole {
						cloud = "Yes"
					}
					fmt.Printf("%-35s %-15s %-10s %-10s %s\n",
						name, ns, bindings, cloud, strings.ToUpper(sa.RiskLevel))
				}
				fmt.Println()
			}

			if len(result.OrphanedIdentities) > 0 {
				fmt.Printf("Orphaned Identities (%d):\n", len(result.OrphanedIdentities))
				fmt.Println(strings.Repeat("-", 80))
				for _, orphan := range result.OrphanedIdentities {
					fmt.Printf("  [%s] %s/%s (%s)\n",
						strings.ToUpper(orphan.RiskLevel), orphan.Namespace, orphan.Name, orphan.Type)
					fmt.Printf("    Reason: %s\n", orphan.OrphanReason)
					if len(orphan.RoleBindings) > 0 {
						fmt.Printf("    Bindings: %s\n", strings.Join(orphan.RoleBindings, ", "))
					}
				}
				fmt.Println()
			}

			if len(result.OverProvisionedAccounts) > 0 {
				fmt.Printf("Over-Provisioned Accounts (%d):\n", len(result.OverProvisionedAccounts))
				fmt.Println(strings.Repeat("-", 80))
				for _, ovp := range result.OverProvisionedAccounts {
					fmt.Printf("  %s/%s - %.0f%% unused permissions\n",
						ovp.Namespace, ovp.Name, ovp.OverProvisionRate*100)
					fmt.Printf("    Granted: %d, Used: %d, Unused: %d\n",
						ovp.GrantedPerms, ovp.UsedPerms, ovp.UnusedPerms)
				}
				fmt.Println()
			}

			if len(result.RightSizingRecommendations) > 0 {
				fmt.Printf("Right-Sizing Recommendations (%d):\n", len(result.RightSizingRecommendations))
				fmt.Println(strings.Repeat("-", 80))
				for _, rec := range result.RightSizingRecommendations {
					fmt.Printf("  [%s] %s/%s\n",
						strings.ToUpper(rec.ImpactLevel), rec.Namespace, rec.Identity)
					fmt.Printf("    %s\n", rec.Reason)
				}
				fmt.Println()
			}

			if len(result.Recommendations) > 0 {
				fmt.Println("Recommendations:")
				for _, rec := range result.Recommendations {
					fmt.Printf("  • %s\n", rec)
				}
			}

			return nil
		},
	}

	cmd.Flags().IntVar(&staleDays, "stale-days", 30, "Days of inactivity to consider identity stale")

	return cmd
}

func serveCmd() *cobra.Command {
	var port int
	var host string
	var enableCORS bool

	cmd := &cobra.Command{
		Use:   "serve",
		Short: "Start the REST API server",
		Long: `Start the IDC REST API server with Swagger documentation.

The server provides REST endpoints for all IDC functionality:
- Scanning and analysis
- Blast radius calculations
- Attack path detection
- RBAC auditing
- OpenShift security audits
- Identity risk scoring
- Smart auto-detection scans

Swagger UI available at: http://<host>:<port>/swagger/

Examples:
  idc serve
  idc serve --port 9090
  idc serve --host 0.0.0.0 --port 8080 --cors`,
		RunE: func(cmd *cobra.Command, args []string) error {
			cfg := api.Config{
				Kubeconfig:    kubeconfig,
				Context:       kubecontext,
				AWSRegion:     awsRegion,
				GCPProject:    gcpProject,
				AzureSubID:    azureSubID,
				EnableSwagger: true,
				EnableCORS:    enableCORS,
			}
			server := api.NewServer(cfg)

			fmt.Printf("Starting IDC API server on %s:%d\n", host, port)
			fmt.Printf("Swagger UI: http://%s:%d/swagger/\n", host, port)
			fmt.Printf("API Health: http://%s:%d/health\n", host, port)

			return server.ListenAndServe(host, port)
		},
	}

	cmd.Flags().IntVar(&port, "port", 8080, "Port to listen on")
	cmd.Flags().StringVar(&host, "host", "localhost", "Host to bind to")
	cmd.Flags().BoolVar(&enableCORS, "cors", false, "Enable CORS for cross-origin requests")

	return cmd
}

func smartScanCmd() *cobra.Command {
	var outputFile string
	var verbose bool

	cmd := &cobra.Command{
		Use:   "smart-scan",
		Short: "Intelligent auto-detection scan",
		Long: `Run an intelligent scan that automatically detects what to analyze.

Smart scan automatically:
- Detects if cluster is OpenShift and runs SCC/Route/OAuth analysis
- Identifies cloud identity bindings (AWS/GCP/Azure) and enables IAM analysis
- Discovers workloads with privileged configurations
- Finds ServiceAccounts with overly permissive RBAC
- Detects attack paths and privilege escalation vectors
- Calculates identity risk scores

This is the recommended way to deploy IDC - it follows the entire identity
chain automatically without requiring manual configuration.

Examples:
  idc smart-scan
  idc smart-scan -A
  idc smart-scan -o json > report.json
  idc smart-scan --verbose`,
		RunE: func(cmd *cobra.Command, args []string) error {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()

			result := runSmartScan(ctx, verbose)

			if outputFormat == "json" {
				data, err := json.MarshalIndent(result, "", "  ")
				if err != nil {
					return err
				}
				if outputFile != "" {
					return os.WriteFile(outputFile, data, 0644)
				}
				fmt.Println(string(data))
				return nil
			}

			printSmartScanResult(result)

			if outputFile != "" {
				data, _ := json.MarshalIndent(result, "", "  ")
				return os.WriteFile(outputFile, data, 0644)
			}

			return nil
		},
	}

	cmd.Flags().StringVar(&outputFile, "output-file", "", "Write results to file")
	cmd.Flags().BoolVar(&verbose, "verbose", false, "Show detailed progress")

	return cmd
}

type SmartScanResult struct {
	ClusterInfo       ClusterDetection                  `json:"cluster_info"`
	PlatformInfo      *analysis.PlatformDetectionResult `json:"platform_info,omitempty"`
	ExecutedScans     []string                          `json:"executed_scans"`
	IdentityRisks     *analysis.IdentityRiskResult      `json:"identity_risks,omitempty"`
	RBACFindings      []analysis.RBACFinding            `json:"rbac_findings,omitempty"`
	ExploitablePerms  *analysis.ExploitablePermResult   `json:"exploitable_permissions,omitempty"`
	AttackPaths       []*analysis.AttackPath            `json:"attack_paths,omitempty"`
	OpenShiftAudit    *analysis.OpenShiftAuditResult    `json:"openshift_audit,omitempty"`
	PodSecurityIssues []analysis.PodSecurityFinding     `json:"pod_security_issues,omitempty"`
	CloudFindings     []analysis.CloudIAMFinding        `json:"cloud_findings,omitempty"`
	PlatformChecks    *analysis.PlatformCheckResult     `json:"platform_checks,omitempty"`
	Compliance        *analysis.ComplianceResult        `json:"compliance,omitempty"`
	Summary           SmartScanSummary                  `json:"summary"`
}

type ClusterDetection struct {
	IsOpenShift        bool     `json:"is_openshift"`
	OpenShiftVersion   string   `json:"openshift_version,omitempty"`
	HasAWSIdentities   bool     `json:"has_aws_identities"`
	HasGCPIdentities   bool     `json:"has_gcp_identities"`
	HasAzureIdentities bool     `json:"has_azure_identities"`
	TotalNamespaces    int      `json:"total_namespaces"`
	TotalWorkloads     int      `json:"total_workloads"`
	TotalServiceAccounts int    `json:"total_service_accounts"`
	DetectedFeatures   []string `json:"detected_features"`
}

type SmartScanSummary struct {
	TotalFindings      int    `json:"total_findings"`
	CriticalCount      int    `json:"critical_count"`
	HighCount          int    `json:"high_count"`
	MediumCount        int    `json:"medium_count"`
	LowCount           int    `json:"low_count"`
	RiskScore          int    `json:"risk_score"`
	OverallRiskLevel   string `json:"overall_risk_level"`
	TopRecommendations []string `json:"top_recommendations"`
}

func runSmartScan(ctx context.Context, verbose bool) *SmartScanResult {
	result := &SmartScanResult{
		ExecutedScans: []string{},
	}

	if verbose {
		fmt.Println("[*] Starting smart scan - auto-detecting cluster configuration...")
	}

	g, err := collectGraph(ctx)
	if err != nil {
		if verbose {
			fmt.Printf("[!] Failed to collect graph: %v\n", err)
		}
		return result
	}

	detection := detectClusterFeatures(g, verbose)
	result.ClusterInfo = detection

	if verbose {
		fmt.Println("\n[*] Detecting platform and cloud identities...")
	}
	result.ExecutedScans = append(result.ExecutedScans, "platform-detection")
	platformResult := analysis.DetectPlatform(g)
	result.PlatformInfo = platformResult

	if verbose {
		fmt.Printf("  [+] Platform: %s\n", platformResult.Primary.Platform)
		fmt.Printf("  [+] Cloud Provider: %s\n", platformResult.Primary.CloudProvider)
		if platformResult.Primary.IsManaged {
			fmt.Println("  [+] Managed Kubernetes service detected")
		}
		if platformResult.Primary.IsServerless {
			fmt.Println("  [+] Serverless platform detected")
		}
	}

	if verbose {
		fmt.Println("\n[*] Analyzing exploitable permissions...")
	}
	result.ExecutedScans = append(result.ExecutedScans, "exploitable-permissions")
	exploitResult := analysis.AnalyzeExploitablePermissions(g, platformResult)
	result.ExploitablePerms = exploitResult

	if verbose {
		fmt.Printf("  [+] Found %d exploitable permissions (%d critical, %d high)\n",
			len(exploitResult.Findings), exploitResult.CriticalCount, exploitResult.HighCount)
	}

	if verbose {
		fmt.Println("\n[*] Running platform-specific security checks...")
	}
	result.ExecutedScans = append(result.ExecutedScans, "platform-checks")
	platformChecks := analysis.RunPlatformChecks(g, platformResult)
	result.PlatformChecks = platformChecks

	if verbose {
		fmt.Printf("  [+] %d/%d checks passed\n", platformChecks.PassedChecks, platformChecks.TotalChecks)
	}

	if verbose {
		fmt.Println("\n[*] Running identity risk analysis...")
	}
	result.ExecutedScans = append(result.ExecutedScans, "identity-risk")
	riskResult := analysis.CalculateIdentityRisk(g, analysis.IdentityRiskOptions{
		TopN: 20,
	})
	result.IdentityRisks = riskResult

	if verbose {
		fmt.Println("[*] Running RBAC audit...")
	}
	result.ExecutedScans = append(result.ExecutedScans, "rbac-audit")
	rbacResult := analysis.RunRBACAudit(g, analysis.RBACAuditOptions{
		IncludeSystem: includeSystem,
	})
	result.RBACFindings = rbacResult.Findings

	if verbose {
		fmt.Println("[*] Detecting attack paths...")
	}
	result.ExecutedScans = append(result.ExecutedScans, "attack-paths")
	attackOpts := analysis.AttackPathOptions{
		IncludeCloud:   detection.HasAWSIdentities || detection.HasGCPIdentities || detection.HasAzureIdentities,
		IncludePrivesc: true,
	}
	attackResults, _ := analysis.FindAllAttackPaths(g, attackOpts)
	var attackPaths []*analysis.AttackPath
	for _, ar := range attackResults {
		attackPaths = append(attackPaths, ar.Paths...)
	}
	if len(attackPaths) > 20 {
		attackPaths = attackPaths[:20]
	}
	result.AttackPaths = attackPaths

	if verbose {
		fmt.Println("[*] Checking pod security...")
	}
	result.ExecutedScans = append(result.ExecutedScans, "pod-security")
	podSecResult := analysis.RunPodSecurityAudit(g, analysis.PodSecurityOptions{
		IncludeSystem: includeSystem,
	})
	result.PodSecurityIssues = podSecResult.Findings

	if detection.IsOpenShift {
		if verbose {
			fmt.Println("[*] OpenShift detected - running OpenShift security audit...")
		}
		result.ExecutedScans = append(result.ExecutedScans, "openshift-audit")
		osResult := analysis.RunOpenShiftAudit(g, analysis.OpenShiftAuditOptions{
			IncludeSystem: includeSystem,
		})
		result.OpenShiftAudit = osResult
	}

	if detection.HasAWSIdentities || detection.HasGCPIdentities || detection.HasAzureIdentities {
		if verbose {
			fmt.Println("[*] Cloud identities detected - running cloud IAM audit...")
		}
		result.ExecutedScans = append(result.ExecutedScans, "cloud-audit")
		cloudResult := analysis.AnalyzeCloudIAM(g)
		result.CloudFindings = cloudResult.Findings
	}

	if verbose {
		fmt.Println("[*] Running compliance framework analysis...")
	}
	result.ExecutedScans = append(result.ExecutedScans, "compliance")
	complianceResult := analysis.RunComplianceAnalysis(g, analysis.ComplianceOptions{
		IncludeSystem: includeSystem,
		IncludeCloud:  detection.HasAWSIdentities || detection.HasGCPIdentities || detection.HasAzureIdentities,
	})
	result.Compliance = complianceResult

	if verbose {
		fmt.Printf("  [+] Overall compliance: %.1f%%\n", complianceResult.Summary.AverageCompliance)
	}

	result.Summary = calculateSmartScanSummary(result)

	if verbose {
		fmt.Printf("\n[+] Smart scan complete - executed %d scan types\n", len(result.ExecutedScans))
	}

	return result
}

func detectClusterFeatures(g *graph.Graph, verbose bool) ClusterDetection {
	detection := ClusterDetection{
		DetectedFeatures: []string{},
	}

	for _, node := range g.GetNodesByType(graph.NodeSCC) {
		detection.IsOpenShift = true
		_ = node
		break
	}

	if detection.IsOpenShift {
		detection.DetectedFeatures = append(detection.DetectedFeatures, "OpenShift SCCs")
		if verbose {
			fmt.Println("  [+] Detected OpenShift cluster")
		}
	}

	routes := g.GetNodesByType(graph.NodeRoute)
	if len(routes) > 0 {
		detection.DetectedFeatures = append(detection.DetectedFeatures, "OpenShift Routes")
	}

	oauthClients := g.GetNodesByType(graph.NodeOAuthClient)
	if len(oauthClients) > 0 {
		detection.DetectedFeatures = append(detection.DetectedFeatures, "OpenShift OAuth")
	}

	for _, node := range g.GetNodesByType(graph.NodeCloudRole) {
		if node.Metadata.CloudProvider == "aws" {
			detection.HasAWSIdentities = true
		} else if node.Metadata.CloudProvider == "gcp" {
			detection.HasGCPIdentities = true
		} else if node.Metadata.CloudProvider == "azure" {
			detection.HasAzureIdentities = true
		}
	}

	if detection.HasAWSIdentities {
		detection.DetectedFeatures = append(detection.DetectedFeatures, "AWS IAM Roles")
		if verbose {
			fmt.Println("  [+] Detected AWS IAM roles for service accounts")
		}
	}
	if detection.HasGCPIdentities {
		detection.DetectedFeatures = append(detection.DetectedFeatures, "GCP Workload Identity")
		if verbose {
			fmt.Println("  [+] Detected GCP Workload Identity bindings")
		}
	}
	if detection.HasAzureIdentities {
		detection.DetectedFeatures = append(detection.DetectedFeatures, "Azure Managed Identity")
		if verbose {
			fmt.Println("  [+] Detected Azure managed identity bindings")
		}
	}

	namespaces := make(map[string]bool)
	for _, node := range g.GetNodesByType(graph.NodeWorkload) {
		namespaces[node.Namespace] = true
	}
	detection.TotalNamespaces = len(namespaces)
	detection.TotalWorkloads = len(g.GetNodesByType(graph.NodeWorkload))
	detection.TotalServiceAccounts = len(g.GetNodesByType(graph.NodeServiceAccount))

	if verbose {
		fmt.Printf("  [+] Found %d namespaces, %d workloads, %d service accounts\n",
			detection.TotalNamespaces, detection.TotalWorkloads, detection.TotalServiceAccounts)
	}

	return detection
}

func calculateSmartScanSummary(result *SmartScanResult) SmartScanSummary {
	summary := SmartScanSummary{
		TopRecommendations: []string{},
	}

	for _, f := range result.RBACFindings {
		summary.TotalFindings++
		switch f.Severity {
		case graph.SeverityCritical:
			summary.CriticalCount++
		case graph.SeverityHigh:
			summary.HighCount++
		case graph.SeverityMedium:
			summary.MediumCount++
		case graph.SeverityLow:
			summary.LowCount++
		}
	}

	for _, f := range result.PodSecurityIssues {
		summary.TotalFindings++
		switch f.Severity {
		case graph.SeverityCritical:
			summary.CriticalCount++
		case graph.SeverityHigh:
			summary.HighCount++
		case graph.SeverityMedium:
			summary.MediumCount++
		case graph.SeverityLow:
			summary.LowCount++
		}
	}

	if result.OpenShiftAudit != nil {
		allFindings := append(result.OpenShiftAudit.RouteFindings, result.OpenShiftAudit.OAuthFindings...)
		allFindings = append(allFindings, result.OpenShiftAudit.BuildFindings...)
		allFindings = append(allFindings, result.OpenShiftAudit.ProjectFindings...)
		allFindings = append(allFindings, result.OpenShiftAudit.RBACFindings...)
		for _, f := range allFindings {
			summary.TotalFindings++
			switch f.Severity {
			case graph.SeverityCritical:
				summary.CriticalCount++
			case graph.SeverityHigh:
				summary.HighCount++
			case graph.SeverityMedium:
				summary.MediumCount++
			case graph.SeverityLow:
				summary.LowCount++
			}
		}
	}

	for _, f := range result.CloudFindings {
		summary.TotalFindings++
		switch f.Severity {
		case graph.SeverityCritical:
			summary.CriticalCount++
		case graph.SeverityHigh:
			summary.HighCount++
		case graph.SeverityMedium:
			summary.MediumCount++
		case graph.SeverityLow:
			summary.LowCount++
		}
	}

	if result.ExploitablePerms != nil {
		for _, f := range result.ExploitablePerms.Findings {
			summary.TotalFindings++
			switch f.Severity {
			case graph.SeverityCritical:
				summary.CriticalCount++
			case graph.SeverityHigh:
				summary.HighCount++
			case graph.SeverityMedium:
				summary.MediumCount++
			case graph.SeverityLow:
				summary.LowCount++
			}
		}
	}

	if result.PlatformChecks != nil {
		for _, f := range result.PlatformChecks.Findings {
			if !f.Passed {
				summary.TotalFindings++
				switch f.Severity {
				case graph.SeverityCritical:
					summary.CriticalCount++
				case graph.SeverityHigh:
					summary.HighCount++
				case graph.SeverityMedium:
					summary.MediumCount++
				case graph.SeverityLow:
					summary.LowCount++
				}
			}
		}
	}

	summary.TotalFindings += len(result.AttackPaths)
	for _, path := range result.AttackPaths {
		switch path.MaxSeverity {
		case graph.SeverityCritical:
			summary.CriticalCount++
		case graph.SeverityHigh:
			summary.HighCount++
		case graph.SeverityMedium:
			summary.MediumCount++
		case graph.SeverityLow:
			summary.LowCount++
		}
	}

	summary.RiskScore = summary.CriticalCount*40 + summary.HighCount*20 + summary.MediumCount*10 + summary.LowCount*5

	if summary.CriticalCount > 0 || summary.RiskScore > 200 {
		summary.OverallRiskLevel = "CRITICAL"
	} else if summary.HighCount > 3 || summary.RiskScore > 100 {
		summary.OverallRiskLevel = "HIGH"
	} else if summary.MediumCount > 5 || summary.RiskScore > 50 {
		summary.OverallRiskLevel = "MEDIUM"
	} else {
		summary.OverallRiskLevel = "LOW"
	}

	if summary.CriticalCount > 0 {
		summary.TopRecommendations = append(summary.TopRecommendations,
			"Address critical findings immediately - these represent severe security risks")
	}
	if result.IdentityRisks != nil && len(result.IdentityRisks.TopRisks) > 0 {
		topRisk := result.IdentityRisks.TopRisks[0]
		if topRisk.RiskScore > 70 {
			summary.TopRecommendations = append(summary.TopRecommendations,
				fmt.Sprintf("Review high-risk identity: %s/%s (score: %d)", topRisk.Namespace, topRisk.Name, topRisk.RiskScore))
		}
	}
	if len(result.AttackPaths) > 0 {
		summary.TopRecommendations = append(summary.TopRecommendations,
			fmt.Sprintf("Investigate %d detected attack paths that could lead to privilege escalation", len(result.AttackPaths)))
	}
	if result.ClusterInfo.IsOpenShift && result.OpenShiftAudit != nil && result.OpenShiftAudit.SCCAnalysis != nil {
		sccIssues := len(result.OpenShiftAudit.SCCAnalysis.RiskyBindings)
		if sccIssues > 0 {
			summary.TopRecommendations = append(summary.TopRecommendations,
				fmt.Sprintf("Review %d Security Context Constraints issues in OpenShift", sccIssues))
		}
	}

	if result.ExploitablePerms != nil && result.ExploitablePerms.CriticalCount > 0 {
		summary.TopRecommendations = append(summary.TopRecommendations,
			fmt.Sprintf("Found %d critical exploitable permissions that could enable cluster compromise",
				result.ExploitablePerms.CriticalCount))
	}

	if result.PlatformChecks != nil && result.PlatformChecks.FailedChecks > 0 {
		summary.TopRecommendations = append(summary.TopRecommendations,
			fmt.Sprintf("Address %d failed platform security checks for %s",
				result.PlatformChecks.FailedChecks, result.PlatformChecks.Platform))
	}

	if result.PlatformInfo != nil {
		if result.PlatformInfo.CloudIdentities.HasAWSIRSA || result.PlatformInfo.CloudIdentities.HasAWSPodIdentity {
			if len(result.PlatformInfo.CloudIdentities.AWSRoleARNs) > 0 {
				summary.TopRecommendations = append(summary.TopRecommendations,
					fmt.Sprintf("Review %d AWS IAM roles mapped to Kubernetes service accounts",
						len(result.PlatformInfo.CloudIdentities.AWSRoleARNs)))
			}
		}
		if result.PlatformInfo.CloudIdentities.HasGCPWorkloadID {
			if len(result.PlatformInfo.CloudIdentities.GCPServiceAccounts) > 0 {
				summary.TopRecommendations = append(summary.TopRecommendations,
					fmt.Sprintf("Review %d GCP service accounts using Workload Identity",
						len(result.PlatformInfo.CloudIdentities.GCPServiceAccounts)))
			}
		}
		if result.PlatformInfo.CloudIdentities.HasAzureWorkloadID || result.PlatformInfo.CloudIdentities.HasAzurePodIdentity {
			if len(result.PlatformInfo.CloudIdentities.AzureClientIDs) > 0 {
				summary.TopRecommendations = append(summary.TopRecommendations,
					fmt.Sprintf("Review %d Azure managed identities bound to Kubernetes",
						len(result.PlatformInfo.CloudIdentities.AzureClientIDs)))
			}
		}
	}

	if result.Compliance != nil {
		if result.Compliance.Summary.CriticalGapsCount > 0 {
			summary.TopRecommendations = append(summary.TopRecommendations,
				fmt.Sprintf("Address %d critical compliance gaps across frameworks",
					result.Compliance.Summary.CriticalGapsCount))
		}
		if result.Compliance.Summary.AverageCompliance < 70 {
			summary.TopRecommendations = append(summary.TopRecommendations,
				fmt.Sprintf("Overall compliance score is %.1f%% - review framework requirements",
					result.Compliance.Summary.AverageCompliance))
		}
	}

	return summary
}

func printSmartScanResult(result *SmartScanResult) {
	fmt.Println()
	fmt.Println("===============================================================")
	fmt.Println("                    IDC SMART SCAN REPORT                       ")
	fmt.Println("===============================================================")

	fmt.Println("\nCLUSTER DETECTION")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("  Namespaces:        %d\n", result.ClusterInfo.TotalNamespaces)
	fmt.Printf("  Workloads:         %d\n", result.ClusterInfo.TotalWorkloads)
	fmt.Printf("  Service Accounts:  %d\n", result.ClusterInfo.TotalServiceAccounts)

	if result.PlatformInfo != nil {
		fmt.Printf("  Platform:          %s\n", result.PlatformInfo.Primary.Platform)
		fmt.Printf("  Cloud Provider:    %s\n", result.PlatformInfo.Primary.CloudProvider)
		if result.PlatformInfo.Primary.IsManaged {
			fmt.Println("  Managed:           Yes")
		}
		if result.PlatformInfo.Primary.IsServerless {
			fmt.Println("  Serverless:        Yes")
		}
		if len(result.PlatformInfo.Primary.Features) > 0 {
			fmt.Printf("  Features:          %s\n", strings.Join(result.PlatformInfo.Primary.Features, ", "))
		}
	} else if result.ClusterInfo.IsOpenShift {
		fmt.Printf("  Platform:          OpenShift")
		if result.ClusterInfo.OpenShiftVersion != "" {
			fmt.Printf(" %s", result.ClusterInfo.OpenShiftVersion)
		}
		fmt.Println()
	} else {
		fmt.Println("  Platform:          Kubernetes")
	}

	if len(result.ClusterInfo.DetectedFeatures) > 0 {
		fmt.Printf("  Detected Features: %s\n", strings.Join(result.ClusterInfo.DetectedFeatures, ", "))
	}

	if result.PlatformInfo != nil {
		fmt.Println("\nCLOUD IDENTITIES")
		fmt.Println(strings.Repeat("-", 50))
		ci := result.PlatformInfo.CloudIdentities
		if ci.HasAWSIRSA {
			fmt.Printf("  AWS IRSA:          %d role(s)\n", len(ci.AWSRoleARNs))
		}
		if ci.HasAWSPodIdentity {
			fmt.Println("  AWS Pod Identity:  Enabled")
		}
		if ci.HasGCPWorkloadID {
			fmt.Printf("  GCP Workload ID:   %d SA(s)\n", len(ci.GCPServiceAccounts))
		}
		if ci.HasAzureWorkloadID {
			fmt.Printf("  Azure Workload ID: %d identity(s)\n", len(ci.AzureClientIDs))
		}
		if ci.HasAzurePodIdentity {
			fmt.Println("  Azure Pod ID:      Enabled")
		}
		if !ci.HasAWSIRSA && !ci.HasAWSPodIdentity && !ci.HasGCPWorkloadID && !ci.HasAzureWorkloadID && !ci.HasAzurePodIdentity {
			fmt.Println("  No cloud identities detected")
		}
	}

	if result.Compliance != nil {
		fmt.Println("\nCOMPLIANCE ANALYSIS")
		fmt.Println(strings.Repeat("-", 50))
		fmt.Printf("  Overall Score:     %.1f%%\n", result.Compliance.OverallScore)
		fmt.Printf("  Critical Gaps:     %d\n", result.Compliance.Summary.CriticalGapsCount)
		fmt.Printf("  High Gaps:         %d\n", result.Compliance.Summary.HighGapsCount)
		fmt.Println()
		for _, fc := range result.Compliance.Frameworks {
			status := "✓"
			if fc.CompliancePercent < 70 {
				status = "✗"
			} else if fc.CompliancePercent < 90 {
				status = "○"
			}
			fmt.Printf("  %s %-15s %.1f%% (%d/%d)\n",
				status, fc.Framework, fc.CompliancePercent, fc.PassedControls, fc.TotalControls)
		}
	}

	fmt.Println("\nEXECUTED SCANS")
	fmt.Println(strings.Repeat("-", 50))
	for _, scan := range result.ExecutedScans {
		fmt.Printf("  [+] %s\n", scan)
	}

	fmt.Println("\nSUMMARY")
	fmt.Println(strings.Repeat("-", 50))
	fmt.Printf("  Total Findings:    %d\n", result.Summary.TotalFindings)
	fmt.Printf("  Risk Score:        %d\n", result.Summary.RiskScore)
	fmt.Printf("  Overall Risk:      %s\n", result.Summary.OverallRiskLevel)
	fmt.Println()
	fmt.Printf("  Critical:          %d\n", result.Summary.CriticalCount)
	fmt.Printf("  High:              %d\n", result.Summary.HighCount)
	fmt.Printf("  Medium:            %d\n", result.Summary.MediumCount)
	fmt.Printf("  Low:               %d\n", result.Summary.LowCount)

	if result.IdentityRisks != nil && len(result.IdentityRisks.TopRisks) > 0 {
		fmt.Println("\nTOP RISKY IDENTITIES")
		fmt.Println(strings.Repeat("-", 50))
		count := len(result.IdentityRisks.TopRisks)
		if count > 5 {
			count = 5
		}
		for i := 0; i < count; i++ {
			id := result.IdentityRisks.TopRisks[i]
			fmt.Printf("  %d. %s/%s (score: %d, %s)\n", i+1, id.Namespace, id.Name, id.RiskScore, id.RiskLevel)
		}
	}

	if len(result.AttackPaths) > 0 {
		fmt.Println("\nTOP ATTACK PATHS")
		fmt.Println(strings.Repeat("-", 50))
		count := len(result.AttackPaths)
		if count > 5 {
			count = 5
		}
		for i := 0; i < count; i++ {
			path := result.AttackPaths[i]
			source := "unknown"
			if path.EntryPoint != nil {
				source = path.EntryPoint.Name
			}
			fmt.Printf("  %d. %s -> %s [%s]\n", i+1, source, path.Objective, strings.ToUpper(string(path.MaxSeverity)))
			fmt.Printf("     %s\n", path.Description)
		}
	}

	if result.ExploitablePerms != nil && len(result.ExploitablePerms.Findings) > 0 {
		fmt.Println("\nEXPLOITABLE PERMISSIONS")
		fmt.Println(strings.Repeat("-", 50))
		fmt.Printf("  Critical:          %d\n", result.ExploitablePerms.CriticalCount)
		fmt.Printf("  High:              %d\n", result.ExploitablePerms.HighCount)
		fmt.Printf("  Medium:            %d\n", result.ExploitablePerms.MediumCount)
		fmt.Printf("  Low:               %d\n", result.ExploitablePerms.LowCount)
		fmt.Println()
		count := len(result.ExploitablePerms.Findings)
		if count > 5 {
			count = 5
		}
		for i := 0; i < count; i++ {
			f := result.ExploitablePerms.Findings[i]
			fmt.Printf("  %d. [%s] %s\n", i+1, strings.ToUpper(string(f.Severity)), f.Title)
			fmt.Printf("     Subject: %s/%s (%s)\n", f.Subject.Namespace, f.Subject.Name, f.Subject.Kind)
			fmt.Printf("     Category: %s\n", f.Category)
		}
	}

	if result.PlatformChecks != nil && result.PlatformChecks.FailedChecks > 0 {
		fmt.Println("\nPLATFORM SECURITY CHECKS")
		fmt.Println(strings.Repeat("-", 50))
		fmt.Printf("  Platform:          %s\n", result.PlatformChecks.Platform)
		fmt.Printf("  Passed:            %d/%d\n", result.PlatformChecks.PassedChecks, result.PlatformChecks.TotalChecks)
		fmt.Printf("  Failed:            %d\n", result.PlatformChecks.FailedChecks)
		fmt.Println()
		count := 0
		for _, f := range result.PlatformChecks.Findings {
			if !f.Passed {
				count++
				if count > 5 {
					break
				}
				fmt.Printf("  %d. [%s] %s\n", count, strings.ToUpper(string(f.Severity)), f.Title)
				fmt.Printf("     %s\n", f.Description)
			}
		}
	}

	if len(result.Summary.TopRecommendations) > 0 {
		fmt.Println("\nTOP RECOMMENDATIONS")
		fmt.Println(strings.Repeat("-", 50))
		for i, rec := range result.Summary.TopRecommendations {
			fmt.Printf("  %d. %s\n", i+1, rec)
		}
	}

	fmt.Println()
}
