package watch

import (
	"context"
	"fmt"
	"os"
	"runtime/debug"
	"sync"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/collector"
	"github.com/nelssec/identity-chain/pkg/graph"
	appsv1 "k8s.io/api/apps/v1"
	batchv1 "k8s.io/api/batch/v1"
	corev1 "k8s.io/api/core/v1"
	rbacv1 "k8s.io/api/rbac/v1"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime"
	"k8s.io/apimachinery/pkg/watch"
	"k8s.io/client-go/kubernetes"
	"k8s.io/client-go/rest"
	"k8s.io/client-go/tools/cache"
	"k8s.io/client-go/tools/clientcmd"
)

type Config struct {
	Kubeconfig     string
	Context        string
	AllNamespaces  bool
	Namespace      string
	IncludeSystem  bool
	ResyncPeriod   time.Duration
	DebouncePeriod time.Duration
	MaxMemoryMB    int
	MetricsAddr    string
	WebhookURL     string
	WebhookHeaders map[string]string
	BaselineFile   string
	AlertOnDrift   bool
	DriftOnly      bool
}

type Watcher struct {
	config     Config
	client     kubernetes.Interface
	informers  []cache.SharedIndexInformer
	stopCh     chan struct{}
	metrics    *Metrics
	webhook    *WebhookNotifier
	mu         sync.Mutex
	lastState  *WatchState
	baseline   *analysis.ScanFindings
	debouncer  *debouncer
	opts       collector.Options
}

type WatchState struct {
	Timestamp      time.Time
	RBACFindings   []analysis.RBACFinding
	PodSecFindings []analysis.PodSecurityFinding
	NetPolFindings []analysis.NetworkPolicyFinding
	Summary        StateSummary
}

type StateSummary struct {
	TotalFindings   int
	CriticalCount   int
	HighCount       int
	MediumCount     int
	LowCount        int
	WorkloadCount   int
	SACount         int
	RoleCount       int
}

type debouncer struct {
	mu       sync.Mutex
	timer    *time.Timer
	period   time.Duration
	callback func()
}

func newDebouncer(period time.Duration, callback func()) *debouncer {
	return &debouncer{
		period:   period,
		callback: callback,
	}
}

func (d *debouncer) trigger() {
	d.mu.Lock()
	defer d.mu.Unlock()

	if d.timer != nil {
		d.timer.Stop()
	}
	d.timer = time.AfterFunc(d.period, d.callback)
}

func New(config Config) (*Watcher, error) {
	if config.MaxMemoryMB > 0 {
		limit := int64(config.MaxMemoryMB) * 1024 * 1024
		debug.SetMemoryLimit(limit)
	}

	var restConfig *rest.Config
	var err error

	if config.Kubeconfig != "" {
		restConfig, err = clientcmd.BuildConfigFromFlags("", config.Kubeconfig)
	} else if config.Context != "" {
		rules := clientcmd.NewDefaultClientConfigLoadingRules()
		overrides := &clientcmd.ConfigOverrides{CurrentContext: config.Context}
		restConfig, err = clientcmd.NewNonInteractiveDeferredLoadingClientConfig(rules, overrides).ClientConfig()
	} else {
		restConfig, err = rest.InClusterConfig()
		if err != nil {
			restConfig, err = clientcmd.BuildConfigFromFlags("", clientcmd.RecommendedHomeFile)
		}
	}
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes config: %w", err)
	}

	client, err := kubernetes.NewForConfig(restConfig)
	if err != nil {
		return nil, fmt.Errorf("failed to create kubernetes client: %w", err)
	}

	w := &Watcher{
		config:  config,
		client:  client,
		stopCh:  make(chan struct{}),
		metrics: NewMetrics(),
		opts: collector.Options{
			Namespace:     config.Namespace,
			AllNamespaces: config.AllNamespaces,
			IncludeSystem: config.IncludeSystem,
		},
	}

	if config.WebhookURL != "" {
		w.webhook = NewWebhookNotifier(config.WebhookURL, config.WebhookHeaders)
	}

	if config.BaselineFile != "" {
		baseline, err := analysis.LoadScanFindings(config.BaselineFile)
		if err != nil {
			return nil, fmt.Errorf("failed to load baseline: %w", err)
		}
		w.baseline = baseline
	}

	w.debouncer = newDebouncer(config.DebouncePeriod, w.analyze)

	return w, nil
}

func (w *Watcher) Run(ctx context.Context) error {
	fmt.Fprintf(os.Stderr, "Starting identity-chain watcher...\n")
	fmt.Fprintf(os.Stderr, "  Resync period: %v\n", w.config.ResyncPeriod)
	fmt.Fprintf(os.Stderr, "  Debounce period: %v\n", w.config.DebouncePeriod)
	if w.config.MaxMemoryMB > 0 {
		fmt.Fprintf(os.Stderr, "  Memory limit: %dMB\n", w.config.MaxMemoryMB)
	}
	if w.config.MetricsAddr != "" {
		fmt.Fprintf(os.Stderr, "  Metrics endpoint: %s\n", w.config.MetricsAddr)
		go w.metrics.Serve(w.config.MetricsAddr)
	}
	if w.config.WebhookURL != "" {
		fmt.Fprintf(os.Stderr, "  Webhook: %s\n", w.config.WebhookURL)
	}
	if w.baseline != nil {
		fmt.Fprintf(os.Stderr, "  Baseline: %s (alert-on-drift=%v, drift-only=%v)\n",
			w.config.BaselineFile, w.config.AlertOnDrift, w.config.DriftOnly)
	}

	if err := w.setupInformers(); err != nil {
		return fmt.Errorf("failed to setup informers: %w", err)
	}

	for _, informer := range w.informers {
		go informer.Run(w.stopCh)
	}

	fmt.Fprintf(os.Stderr, "Waiting for informer caches to sync...\n")
	for _, informer := range w.informers {
		if !cache.WaitForCacheSync(w.stopCh, informer.HasSynced) {
			return fmt.Errorf("failed to sync informer cache")
		}
	}
	fmt.Fprintf(os.Stderr, "Caches synced, performing initial analysis...\n")

	w.analyze()

	fmt.Fprintf(os.Stderr, "Watching for changes...\n")

	<-ctx.Done()
	close(w.stopCh)
	return nil
}

func (w *Watcher) setupInformers() error {
	namespace := w.config.Namespace
	if w.config.AllNamespaces {
		namespace = metav1.NamespaceAll
	}

	handlers := cache.ResourceEventHandlerFuncs{
		AddFunc:    func(obj interface{}) { w.debouncer.trigger() },
		UpdateFunc: func(old, new interface{}) { w.debouncer.trigger() },
		DeleteFunc: func(obj interface{}) { w.debouncer.trigger() },
	}

	w.informers = append(w.informers, w.createInformer(
		&corev1.ServiceAccount{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.CoreV1().ServiceAccounts(namespace).List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.CoreV1().ServiceAccounts(namespace).Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&rbacv1.Role{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.RbacV1().Roles(namespace).List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.RbacV1().Roles(namespace).Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&rbacv1.ClusterRole{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.RbacV1().ClusterRoles().List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.RbacV1().ClusterRoles().Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&rbacv1.RoleBinding{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.RbacV1().RoleBindings(namespace).List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.RbacV1().RoleBindings(namespace).Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&rbacv1.ClusterRoleBinding{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.RbacV1().ClusterRoleBindings().List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.RbacV1().ClusterRoleBindings().Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&appsv1.Deployment{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.AppsV1().Deployments(namespace).List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.AppsV1().Deployments(namespace).Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&appsv1.StatefulSet{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.AppsV1().StatefulSets(namespace).List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.AppsV1().StatefulSets(namespace).Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&appsv1.DaemonSet{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.AppsV1().DaemonSets(namespace).List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.AppsV1().DaemonSets(namespace).Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&batchv1.Job{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.BatchV1().Jobs(namespace).List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.BatchV1().Jobs(namespace).Watch(context.Background(), opts)
		},
		handlers,
	))

	w.informers = append(w.informers, w.createInformer(
		&batchv1.CronJob{},
		func(opts metav1.ListOptions) (runtime.Object, error) {
			return w.client.BatchV1().CronJobs(namespace).List(context.Background(), opts)
		},
		func(opts metav1.ListOptions) (watch.Interface, error) {
			return w.client.BatchV1().CronJobs(namespace).Watch(context.Background(), opts)
		},
		handlers,
	))

	return nil
}

func (w *Watcher) createInformer(
	objType runtime.Object,
	listFunc func(opts metav1.ListOptions) (runtime.Object, error),
	watchFunc func(opts metav1.ListOptions) (watch.Interface, error),
	handlers cache.ResourceEventHandlerFuncs,
) cache.SharedIndexInformer {
	lw := &cache.ListWatch{
		ListFunc: func(opts metav1.ListOptions) (runtime.Object, error) {
			return listFunc(opts)
		},
		WatchFunc: func(opts metav1.ListOptions) (watch.Interface, error) {
			return watchFunc(opts)
		},
	}

	informer := cache.NewSharedIndexInformer(lw, objType, w.config.ResyncPeriod, cache.Indexers{})
	informer.AddEventHandler(handlers)
	return informer
}

func (w *Watcher) analyze() {
	w.mu.Lock()
	defer w.mu.Unlock()

	start := time.Now()

	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	g, err := w.collectGraph(ctx)
	if err != nil {
		fmt.Fprintf(os.Stderr, "ERROR: Failed to collect graph: %v\n", err)
		return
	}

	ns := w.config.Namespace
	if w.config.AllNamespaces {
		ns = ""
	}

	rbacResult := analysis.RunRBACAudit(g, analysis.RBACAuditOptions{
		Namespace:     ns,
		IncludeSystem: w.config.IncludeSystem,
	})

	podSecResult := analysis.RunPodSecurityAudit(g, analysis.PodSecurityOptions{
		Namespace:     ns,
		IncludeSystem: w.config.IncludeSystem,
	})

	netPolResult := analysis.RunNetworkPolicyAudit(g, analysis.NetworkPolicyOptions{
		Namespace:     ns,
		IncludeSystem: w.config.IncludeSystem,
	})

	newState := &WatchState{
		Timestamp:      time.Now(),
		RBACFindings:   rbacResult.Findings,
		PodSecFindings: podSecResult.Findings,
		NetPolFindings: netPolResult.Findings,
	}

	stats := g.Stats()
	newState.Summary.WorkloadCount = stats.NodeCounts[graph.NodeWorkload]
	newState.Summary.SACount = stats.NodeCounts[graph.NodeServiceAccount]
	newState.Summary.RoleCount = stats.NodeCounts[graph.NodeRole]

	for _, f := range rbacResult.Findings {
		w.countSeverity(&newState.Summary, string(f.Severity))
	}
	for _, f := range podSecResult.Findings {
		w.countSeverity(&newState.Summary, string(f.Severity))
	}
	for _, f := range netPolResult.Findings {
		w.countSeverity(&newState.Summary, string(f.Severity))
	}
	newState.Summary.TotalFindings = newState.Summary.CriticalCount + newState.Summary.HighCount +
		newState.Summary.MediumCount + newState.Summary.LowCount

	w.metrics.Update(newState)

	if w.lastState != nil && w.webhook != nil {
		newFindings := w.diffFindings(w.lastState, newState)
		if len(newFindings) > 0 {
			w.webhook.Send(newFindings)
		}
	}

	// Baseline drift detection
	if w.baseline != nil {
		currentFindings := &analysis.ScanFindings{
			RBACFindings:   newState.RBACFindings,
			PodSecFindings: newState.PodSecFindings,
			NetPolFindings: newState.NetPolFindings,
		}
		diff := analysis.ComputeDiff(w.baseline, currentFindings)

		if diff.Summary.Status != "unchanged" {
			if w.config.AlertOnDrift || w.config.DriftOnly {
				fmt.Fprintf(os.Stderr, "DRIFT DETECTED: status=%s new=%d resolved=%d unchanged=%d\n",
					diff.Summary.Status, diff.Summary.NewCount, diff.Summary.ResolvedCount, diff.UnchangedCount)
				for _, f := range diff.NewFindings {
					fmt.Fprintf(os.Stderr, "  + [%s] %s - %s", f.Severity, f.CheckID, f.Title)
					if f.Namespace != "" {
						fmt.Fprintf(os.Stderr, " (%s/%s)", f.Namespace, f.Resource)
					}
					fmt.Fprintln(os.Stderr)
				}
				for _, f := range diff.ResolvedFindings {
					fmt.Fprintf(os.Stderr, "  - [%s] %s - %s", f.Severity, f.CheckID, f.Title)
					if f.Namespace != "" {
						fmt.Fprintf(os.Stderr, " (%s/%s)", f.Namespace, f.Resource)
					}
					fmt.Fprintln(os.Stderr)
				}
			}

			if w.webhook != nil {
				w.webhook.SendDrift(diff)
			}
		}
	}

	elapsed := time.Since(start)

	if w.config.DriftOnly && w.baseline != nil {
		// In drift-only mode, skip the normal analysis output unless there's drift
		w.lastState = newState
		return
	}

	fmt.Fprintf(os.Stderr, "[%s] Analysis complete in %v: %d findings (critical=%d, high=%d, medium=%d, low=%d)\n",
		newState.Timestamp.Format("15:04:05"),
		elapsed.Round(time.Millisecond),
		newState.Summary.TotalFindings,
		newState.Summary.CriticalCount,
		newState.Summary.HighCount,
		newState.Summary.MediumCount,
		newState.Summary.LowCount,
	)

	w.lastState = newState
}

func (w *Watcher) countSeverity(s *StateSummary, severity string) {
	switch severity {
	case "critical":
		s.CriticalCount++
	case "high":
		s.HighCount++
	case "medium":
		s.MediumCount++
	case "low":
		s.LowCount++
	}
}

func (w *Watcher) collectGraph(ctx context.Context) (*graph.Graph, error) {
	k8sCollector, err := collector.NewKubernetesCollector(w.opts)
	if err != nil {
		return nil, err
	}

	builder := graph.NewBuilder()
	if err := k8sCollector.Collect(ctx, builder); err != nil {
		return nil, err
	}

	builder.BuildResourceEdges()
	return builder.Build(), nil
}

func (w *Watcher) diffFindings(old, new *WatchState) []FindingChange {
	var changes []FindingChange

	oldRBAC := make(map[string]bool)
	for _, f := range old.RBACFindings {
		oldRBAC[f.CheckID+":"+findingKey(f.Affected)] = true
	}
	for _, f := range new.RBACFindings {
		key := f.CheckID + ":" + findingKey(f.Affected)
		if !oldRBAC[key] {
			changes = append(changes, FindingChange{
				Type:     "rbac",
				CheckID:  f.CheckID,
				Name:     f.Title,
				Severity: string(f.Severity),
				Affected: formatAffected(f.Affected),
			})
		}
	}

	oldPodSec := make(map[string]bool)
	for _, f := range old.PodSecFindings {
		oldPodSec[f.CheckID+":"+podSecFindingKey(f.Affected)] = true
	}
	for _, f := range new.PodSecFindings {
		key := f.CheckID + ":" + podSecFindingKey(f.Affected)
		if !oldPodSec[key] {
			changes = append(changes, FindingChange{
				Type:     "pod_security",
				CheckID:  f.CheckID,
				Name:     f.Title,
				Severity: string(f.Severity),
				Affected: formatPodSecAffected(f.Affected),
			})
		}
	}

	return changes
}

func findingKey(affected []analysis.AffectedResource) string {
	if len(affected) == 0 {
		return ""
	}
	return affected[0].Namespace + "/" + affected[0].Name
}

func podSecFindingKey(affected []analysis.AffectedWorkload) string {
	if len(affected) == 0 {
		return ""
	}
	return affected[0].Namespace + "/" + affected[0].Name
}

func formatAffected(affected []analysis.AffectedResource) string {
	if len(affected) == 0 {
		return ""
	}
	a := affected[0]
	if a.Namespace != "" {
		return a.Namespace + "/" + a.Name
	}
	return a.Name
}

func formatPodSecAffected(affected []analysis.AffectedWorkload) string {
	if len(affected) == 0 {
		return ""
	}
	a := affected[0]
	if a.Namespace != "" {
		return a.Namespace + "/" + a.Name
	}
	return a.Name
}

type FindingChange struct {
	Type     string `json:"type"`
	CheckID  string `json:"check_id"`
	Name     string `json:"name"`
	Severity string `json:"severity"`
	Affected string `json:"affected"`
}
