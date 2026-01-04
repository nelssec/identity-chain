package main

import (
	"context"
	"fmt"
	"os"
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
	rootCmd.PersistentFlags().StringVarP(&outputFormat, "output", "o", "table", "Output format: table, json, dot, html")
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

			kind, ns, name := graph.ParseWorkloadRef(workload, namespace)
			nodeID := graph.GenerateNodeID(graph.NodeWorkload, ns, name)

			node := g.GetNode(nodeID)
			if node == nil {
				nodes := g.GetNodesByNamespace(ns)
				for _, n := range nodes {
					if n.Type == graph.NodeWorkload && n.Name == name {
						if kind == "" || n.Metadata.WorkloadKind == kind {
							nodeID = n.ID
							break
						}
					}
				}
			}

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
	var showAzure bool
	var showAWS bool
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
				fmt.Printf("━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━\n")
				fmt.Printf("📌 %s/%s\n", sa.Namespace, sa.Name)

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
									fmt.Printf("   ├─ Role: %s\n", ra.RoleName)
									fmt.Printf("   │  Scope: %s\n", truncateScope(ra.Scope))
									if len(ra.Actions) > 0 {
										fmt.Printf("   │  Actions: %v\n", truncateActions(ra.Actions, 3))
									}
									if len(ra.DataActions) > 0 {
										fmt.Printf("   │  DataActions: %v\n", truncateActions(ra.DataActions, 3))
									}
								}
							} else if err != nil {
								fmt.Printf("   ⚠ Could not fetch Azure roles: %v\n", err)
							}
						} else {
							fmt.Printf("   ℹ Use --azure-subscription to fetch role details\n")
						}

					case "AWS":
						if awsCollector != nil {
							roleInfo, err := awsCollector.CollectRole(ctx, sa.Metadata.CloudRoleARN)
							if err == nil && len(roleInfo.Policies) > 0 {
								fmt.Printf("\n   AWS IAM Policies:\n")
								for _, policy := range roleInfo.Policies {
									fmt.Printf("   ├─ Policy: %s\n", policy.Name)
									if policy.IsAdmin {
										fmt.Printf("   │  ⚠ ADMIN POLICY\n")
									}
									for _, stmt := range policy.Statements {
										if len(stmt.Action) > 0 {
											fmt.Printf("   │  Actions: %v\n", truncateActions(stmt.Action, 3))
										}
									}
								}
							} else if err != nil {
								fmt.Printf("   ⚠ Could not fetch AWS roles: %v\n", err)
							}
						} else {
							fmt.Printf("   ℹ Use --aws-region to fetch role details\n")
						}
					}
				}

				workloads := g.GetWorkloadsUsingSA(sa.ID)
				if len(workloads) > 0 {
					fmt.Printf("\n   Used by workloads:\n")
					for _, w := range workloads {
						fmt.Printf("   └─ %s/%s (%s)\n", w.Namespace, w.Name, w.Metadata.WorkloadKind)
					}
				} else {
					fmt.Printf("\n   ⚠ UNUSED - No workloads using this SA\n")
				}

				fmt.Println()
			}

			if azureWorkspaceID != "" {
				fmt.Println("\n=== Azure Audit Log Usage ===")
				fmt.Println("Querying Azure Log Analytics for recent activity...")

				source, err := audit.NewAzureLogAnalyticsSource(azureWorkspaceID)
				if err != nil {
					fmt.Printf("⚠ Could not connect to Log Analytics: %v\n", err)
				} else {
					opts := audit.QueryOptions{
						StartTime: time.Now().Add(-24 * time.Hour),
						EndTime:   time.Now(),
					}
					events, err := source.GetEvents(ctx, opts)
					if err != nil {
						fmt.Printf("⚠ Query failed: %v\n", err)
					} else {
						fmt.Printf("Found %d audit events in last 24h\n", len(events))
					}
				}
			}

			return nil
		},
	}

	cmd.Flags().BoolVar(&showAzure, "azure", false, "Show Azure identity details")
	cmd.Flags().BoolVar(&showAWS, "aws", false, "Show AWS identity details")
	cmd.Flags().StringVar(&azureWorkspaceID, "azure-workspace", "", "Azure Log Analytics workspace ID for usage data")

	return cmd
}

func detectCloudProvider(identity string) string {
	if len(identity) == 36 && identity[8] == '-' && identity[13] == '-' {
		return "Azure"
	}
	if len(identity) > 12 && identity[:4] == "arn:" {
		return "AWS"
	}
	if len(identity) > 0 && (identity[len(identity)-19:] == ".iam.gserviceaccount" ||
		(len(identity) > 30 && identity[len(identity)-30:] == ".iam.gserviceaccount.com")) {
		return "GCP"
	}
	if len(identity) > 20 && (identity[len(identity)-20:] == "iam.gserviceaccount.com" ||
		len(identity) > 4 && identity[len(identity)-4:] == ".com") {
		return "GCP"
	}
	return "Unknown"
}

func truncateScope(scope string) string {
	if len(scope) > 80 {
		parts := make([]string, 0)
		for i, p := range splitScope(scope) {
			if i > 2 {
				parts = append(parts, "...")
				break
			}
			parts = append(parts, p)
		}
		return joinScope(parts)
	}
	return scope
}

func splitScope(scope string) []string {
	var parts []string
	current := ""
	for _, c := range scope {
		if c == '/' {
			if current != "" {
				parts = append(parts, current)
			}
			current = ""
		} else {
			current += string(c)
		}
	}
	if current != "" {
		parts = append(parts, current)
	}
	return parts
}

func joinScope(parts []string) string {
	result := ""
	for i, p := range parts {
		if i > 0 {
			result += "/"
		}
		result += p
	}
	return result
}

func truncateActions(actions []string, max int) []string {
	if len(actions) <= max {
		return actions
	}
	result := actions[:max]
	result = append(result, fmt.Sprintf("+%d more", len(actions)-max))
	return result
}
