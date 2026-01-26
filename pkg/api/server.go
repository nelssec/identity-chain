package api

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"

	"github.com/nelssec/identity-chain/pkg/analysis"
	"github.com/nelssec/identity-chain/pkg/collector"
	"github.com/nelssec/identity-chain/pkg/collector/cloud"
	"github.com/nelssec/identity-chain/pkg/graph"
)

type Server struct {
	config     Config
	mux        *http.ServeMux
	httpServer *http.Server
}

type Config struct {
	ListenAddr    string
	Kubeconfig    string
	Context       string
	AWSRegion     string
	GCPProject    string
	AzureSubID    string
	ReadTimeout   time.Duration
	WriteTimeout  time.Duration
	EnableCORS    bool
	EnableSwagger bool
}

type APIResponse struct {
	Success bool        `json:"success"`
	Data    interface{} `json:"data,omitempty"`
	Error   *APIError   `json:"error,omitempty"`
	Meta    *APIMeta    `json:"meta,omitempty"`
}

type APIError struct {
	Code    string `json:"code"`
	Message string `json:"message"`
	Details string `json:"details,omitempty"`
}

type APIMeta struct {
	RequestID  string `json:"request_id,omitempty"`
	Duration   string `json:"duration,omitempty"`
	APIVersion string `json:"api_version"`
}

func NewServer(cfg Config) *Server {
	if cfg.ReadTimeout == 0 {
		cfg.ReadTimeout = 5 * time.Minute
	}
	if cfg.WriteTimeout == 0 {
		cfg.WriteTimeout = 5 * time.Minute
	}

	s := &Server{
		config: cfg,
		mux:    http.NewServeMux(),
	}

	s.registerRoutes()

	s.httpServer = &http.Server{
		Addr:         cfg.ListenAddr,
		Handler:      s.middleware(s.mux),
		ReadTimeout:  cfg.ReadTimeout,
		WriteTimeout: cfg.WriteTimeout,
	}

	return s
}

func (s *Server) registerRoutes() {
	s.mux.HandleFunc("/health", s.handleHealth)
	s.mux.HandleFunc("/ready", s.handleReady)

	s.mux.HandleFunc("/api/v1/scan", s.handleScan)
	s.mux.HandleFunc("/api/v1/graph", s.handleGraph)

	s.mux.HandleFunc("/api/v1/blast", s.handleBlast)
	s.mux.HandleFunc("/api/v1/blast/workload", s.handleBlastWorkload)

	s.mux.HandleFunc("/api/v1/attack-paths", s.handleAttackPaths)
	s.mux.HandleFunc("/api/v1/privesc", s.handlePrivesc)

	s.mux.HandleFunc("/api/v1/rbac/audit", s.handleRBACAudit)
	s.mux.HandleFunc("/api/v1/rbac/whocan", s.handleWhocan)
	s.mux.HandleFunc("/api/v1/rbac/whatcan", s.handleWhatcan)

	s.mux.HandleFunc("/api/v1/pod-security", s.handlePodSecurity)
	s.mux.HandleFunc("/api/v1/network-policy", s.handleNetworkPolicy)

	s.mux.HandleFunc("/api/v1/cloud/audit", s.handleCloudAudit)
	s.mux.HandleFunc("/api/v1/cloud/identity", s.handleCloudIdentity)

	s.mux.HandleFunc("/api/v1/openshift/audit", s.handleOpenShiftAudit)
	s.mux.HandleFunc("/api/v1/openshift/scc", s.handleSCCAnalysis)
	s.mux.HandleFunc("/api/v1/openshift/scc/simulate", s.handleSCCSimulate)

	s.mux.HandleFunc("/api/v1/identity/risk", s.handleIdentityRisk)
	s.mux.HandleFunc("/api/v1/identity/lifecycle", s.handleSALifecycle)

	s.mux.HandleFunc("/api/v1/compliance", s.handleCompliance)
	s.mux.HandleFunc("/api/v1/identity/chain", s.handleIdentityChain)
	s.mux.HandleFunc("/api/v1/identity/groups", s.handleGroupAnalysis)
	s.mux.HandleFunc("/api/v1/identity/usage", s.handleUsageAnalysis)

	s.mux.HandleFunc("/api/v1/remediate", s.handleRemediate)

	s.mux.HandleFunc("/api/v1/snapshot", s.handleSnapshot)
	s.mux.HandleFunc("/api/v1/diff", s.handleDiff)

	s.mux.HandleFunc("/api/v1/smart-scan", s.handleSmartScan)

	if s.config.EnableSwagger {
		s.mux.HandleFunc("/swagger.json", s.handleSwaggerJSON)
		s.mux.HandleFunc("/swagger/", s.handleSwaggerUI)
		s.mux.HandleFunc("/docs", s.handleDocsRedirect)
	}
}

func (s *Server) middleware(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		start := time.Now()

		if s.config.EnableCORS {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
			w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")

			if r.Method == "OPTIONS" {
				w.WriteHeader(http.StatusOK)
				return
			}
		}

		w.Header().Set("Content-Type", "application/json")
		w.Header().Set("X-API-Version", "1.0.0")
		w.Header().Set("X-Request-Duration", time.Since(start).String())

		next.ServeHTTP(w, r)
	})
}

func (s *Server) Start() error {
	return s.httpServer.ListenAndServe()
}

func (s *Server) Shutdown(ctx context.Context) error {
	return s.httpServer.Shutdown(ctx)
}

func (s *Server) collectGraph(ctx context.Context, params QueryParams) (*graph.Graph, error) {
	opts := collector.Options{
		KubeConfigPath: s.config.Kubeconfig,
		KubeContext:    s.config.Context,
		Namespace:      params.Namespace,
		AllNamespaces:  params.AllNamespaces,
		IncludeSystem:  params.IncludeSystem,
	}

	k8sCollector, err := collector.NewKubernetesCollector(opts)
	if err != nil {
		return nil, fmt.Errorf("failed to create collector: %w", err)
	}

	builder := graph.NewBuilder()
	if err := k8sCollector.Collect(ctx, builder); err != nil {
		return nil, fmt.Errorf("failed to collect kubernetes data: %w", err)
	}

	if params.IncludeCloud {
		cloudCollector := cloud.NewMultiCloudCollector()
		if s.config.AWSRegion != "" {
			if awsCollector, err := cloud.NewAWSCollector(ctx, s.config.AWSRegion); err == nil {
				cloudCollector.Register(awsCollector)
			}
		}
		for _, sa := range builder.Graph().GetNodesByType(graph.NodeServiceAccount) {
			cloudCollector.CollectForServiceAccount(ctx, builder, sa)
		}
	}

	osOpts := collector.Options{
		KubeConfigPath: s.config.Kubeconfig,
		KubeContext:    s.config.Context,
		Namespace:      params.Namespace,
		AllNamespaces:  params.AllNamespaces,
		IncludeSystem:  params.IncludeSystem,
	}
	if osCollector, err := collector.NewOpenShiftCollector(osOpts); err == nil {
		osCollector.Collect(ctx, builder)
	}

	return builder.Graph(), nil
}

func (s *Server) writeJSON(w http.ResponseWriter, status int, data interface{}) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIResponse{
		Success: status >= 200 && status < 300,
		Data:    data,
		Meta: &APIMeta{
			APIVersion: "1.0.0",
		},
	})
}

func (s *Server) writeError(w http.ResponseWriter, status int, code, message string) {
	w.WriteHeader(status)
	json.NewEncoder(w).Encode(APIResponse{
		Success: false,
		Error: &APIError{
			Code:    code,
			Message: message,
		},
		Meta: &APIMeta{
			APIVersion: "1.0.0",
		},
	})
}

type QueryParams struct {
	Namespace     string
	AllNamespaces bool
	IncludeSystem bool
	IncludeCloud  bool
	Workload      string
	Verb          string
	Resource      string
	ServiceAccount string
	CheckIDs      []string
	SkipCheckIDs  []string
	Severity      string
	TopN          int
	MinScore      int
}

func parseQueryParams(r *http.Request) QueryParams {
	q := r.URL.Query()
	params := QueryParams{
		Namespace:      q.Get("namespace"),
		AllNamespaces:  q.Get("all_namespaces") == "true" || q.Get("allNamespaces") == "true",
		IncludeSystem:  q.Get("include_system") == "true" || q.Get("includeSystem") == "true",
		IncludeCloud:   q.Get("include_cloud") == "true" || q.Get("includeCloud") == "true",
		Workload:       q.Get("workload"),
		Verb:           q.Get("verb"),
		Resource:       q.Get("resource"),
		ServiceAccount: getFirstNonEmpty(q.Get("service_account"), q.Get("serviceAccount")),
		Severity:       q.Get("severity"),
	}

	if checks := q.Get("checks"); checks != "" {
		params.CheckIDs = strings.Split(checks, ",")
	}
	if skip := q.Get("skip_checks"); skip != "" {
		params.SkipCheckIDs = strings.Split(skip, ",")
	}
	if topN := q.Get("top"); topN != "" {
		params.TopN, _ = strconv.Atoi(topN)
	}
	if minScore := q.Get("min_score"); minScore != "" {
		params.MinScore, _ = strconv.Atoi(minScore)
	}

	if params.Namespace == "" && !params.AllNamespaces {
		params.Namespace = "default"
	}

	return params
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "healthy"})
}

func (s *Server) handleReady(w http.ResponseWriter, r *http.Request) {
	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Second)
	defer cancel()

	opts := collector.Options{
		KubeConfigPath: s.config.Kubeconfig,
		KubeContext:    s.config.Context,
		Namespace:      "default",
	}

	_, err := collector.NewKubernetesCollector(opts)
	if err != nil {
		s.writeError(w, http.StatusServiceUnavailable, "NOT_READY", "Cannot connect to Kubernetes cluster")
		return
	}

	_ = ctx
	s.writeJSON(w, http.StatusOK, map[string]string{"status": "ready"})
}

func (s *Server) handleScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	s.writeJSON(w, http.StatusOK, g.Stats())
}

func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	result := map[string]interface{}{
		"nodes": g.AllNodes(),
		"edges": g.AllEdges(),
		"stats": g.Stats(),
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleBlast(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	results, err := analysis.AllWorkloadBlastRadius(g)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "BLAST_FAILED", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleBlastWorkload(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	params := parseQueryParams(r)
	if params.Workload == "" {
		s.writeError(w, http.StatusBadRequest, "MISSING_PARAM", "workload parameter is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	kind, ns, name := graph.ParseWorkloadRef(params.Workload, params.Namespace)
	nodeID := graph.GenerateNodeID(graph.NodeWorkload, ns, name)
	_ = kind

	result, err := analysis.BlastRadius(g, nodeID)
	if err != nil || result == nil {
		s.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workload not found")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleAttackPaths(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.AttackPathOptions{
		IncludeCloud:   params.IncludeCloud,
		IncludePrivesc: true,
		Namespace:      params.Namespace,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	results, err := analysis.FindAllAttackPaths(g, opts)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "ATTACK_PATH_FAILED", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"results": results,
		"summary": analysis.SummarizeAttackPaths(results),
	})
}

func (s *Server) handlePrivesc(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	results, err := analysis.FindAllPrivescPaths(g, 5)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "PRIVESC_FAILED", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, results)
}

func (s *Server) handleRBACAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.RBACAuditOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
		ChecksToRun:   params.CheckIDs,
		SkipChecks:    params.SkipCheckIDs,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	result := analysis.RunRBACAudit(g, opts)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleWhocan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	params := parseQueryParams(r)
	if params.Verb == "" || params.Resource == "" {
		s.writeError(w, http.StatusBadRequest, "MISSING_PARAM", "verb and resource parameters are required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	query := analysis.WhoCanQuery{
		Verb:      params.Verb,
		Resource:  params.Resource,
		Namespace: params.Namespace,
	}
	if params.AllNamespaces {
		query.Namespace = ""
	}

	result, err := analysis.WhoCan(g, query)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "WHOCAN_FAILED", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleWhatcan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	params := parseQueryParams(r)
	if params.ServiceAccount == "" {
		s.writeError(w, http.StatusBadRequest, "MISSING_PARAM", "service_account parameter is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	query := analysis.ReverseRBACQuery{
		SubjectKind: "ServiceAccount",
		SubjectName: params.ServiceAccount,
		Namespace:   params.Namespace,
	}
	result, err := analysis.WhatCan(g, query)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "WHATCAN_FAILED", err.Error())
		return
	}
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handlePodSecurity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.PodSecurityOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	result := analysis.RunPodSecurityAudit(g, opts)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleNetworkPolicy(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.NetworkPolicyOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	result := analysis.RunNetworkPolicyAudit(g, opts)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCloudAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	params.IncludeCloud = true

	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	result := analysis.AnalyzeCloudIAM(g)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCloudIdentity(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	params.IncludeCloud = true

	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	serviceAccounts := g.GetNodesByType(graph.NodeServiceAccount)
	var identities []map[string]interface{}

	for _, sa := range serviceAccounts {
		if sa.HasCloudIdentity() {
			identity := map[string]interface{}{
				"name":      sa.Name,
				"namespace": sa.Namespace,
			}
			if sa.Metadata.CloudRoleARN != "" {
				identity["aws_role_arn"] = sa.Metadata.CloudRoleARN
			}
			if sa.Metadata.GCPServiceAccount != "" {
				identity["gcp_service_account"] = sa.Metadata.GCPServiceAccount
			}
			if sa.Metadata.AzureManagedID != "" {
				identity["azure_managed_id"] = sa.Metadata.AzureManagedID
			}
			identities = append(identities, identity)
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"identities": identities,
		"total":      len(identities),
	})
}

func (s *Server) handleOpenShiftAudit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.OpenShiftAuditOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	result := analysis.RunOpenShiftAudit(g, opts)

	if !result.IsOpenShift {
		s.writeError(w, http.StatusBadRequest, "NOT_OPENSHIFT", "This cluster is not an OpenShift cluster")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSCCAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	result := analysis.AnalyzeSCCs(g)
	if len(result.SCCs) == 0 {
		s.writeError(w, http.StatusBadRequest, "NOT_OPENSHIFT", "No SCCs found - this may not be an OpenShift cluster")
		return
	}

	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSCCSimulate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	params := parseQueryParams(r)
	if params.Workload == "" {
		s.writeError(w, http.StatusBadRequest, "MISSING_PARAM", "workload parameter is required")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	_, ns, name := graph.ParseWorkloadRef(params.Workload, params.Namespace)
	nodeID := graph.GenerateNodeID(graph.NodeWorkload, ns, name)
	workloadNode := g.GetNode(nodeID)
	if workloadNode == nil {
		s.writeError(w, http.StatusNotFound, "NOT_FOUND", "Workload not found")
		return
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
		s.writeError(w, http.StatusNotFound, "NOT_FOUND", "ServiceAccount not found for workload")
		return
	}

	sccResult := analysis.AnalyzeSCCs(g)
	if len(sccResult.SCCs) == 0 {
		s.writeError(w, http.StatusBadRequest, "NOT_OPENSHIFT", "No SCCs found")
		return
	}

	saRef := "system:serviceaccount:" + saNode.Namespace + ":" + saNode.Name

	var availableSCCs []map[string]interface{}
	for _, binding := range sccResult.SCCBindings {
		match := false
		if binding.SubjectType == "ServiceAccount" &&
			binding.SubjectNS == saNode.Namespace &&
			binding.SubjectName == saNode.Name {
			match = true
		}
		if binding.SubjectType == "User" && binding.SubjectName == saRef {
			match = true
		}
		if binding.SubjectType == "Group" {
			if binding.SubjectName == "system:serviceaccounts" ||
				binding.SubjectName == "system:serviceaccounts:"+saNode.Namespace ||
				binding.SubjectName == "system:authenticated" {
				match = true
			}
		}

		if match {
			sccDetail := sccResult.GetSCCByName(binding.SCCName)
			if sccDetail != nil {
				availableSCCs = append(availableSCCs, map[string]interface{}{
					"name":         sccDetail.Name,
					"priority":     sccDetail.Priority,
					"risk_level":   sccDetail.RiskLevel,
					"allowed_flags": sccDetail.AllowedFlags,
				})
			}
		}
	}

	var selectedSCC map[string]interface{}
	highestPriority := -1000
	for _, scc := range availableSCCs {
		if priority, ok := scc["priority"].(int); ok && priority > highestPriority {
			highestPriority = priority
			selectedSCC = scc
		}
	}

	s.writeJSON(w, http.StatusOK, map[string]interface{}{
		"workload": map[string]string{
			"name":      workloadNode.Name,
			"namespace": workloadNode.Namespace,
		},
		"service_account": map[string]string{
			"name":      saNode.Name,
			"namespace": saNode.Namespace,
		},
		"available_sccs": availableSCCs,
		"selected_scc":   selectedSCC,
	})
}

func (s *Server) handleIdentityRisk(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.IdentityRiskOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
		MinScore:      params.MinScore,
		TopN:          params.TopN,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}
	if opts.TopN == 0 {
		opts.TopN = 10
	}

	result := analysis.CalculateIdentityRisk(g, opts)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleSALifecycle(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 2*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.SALifecycleOptions{
		IncludeSystem: params.IncludeSystem,
	}

	result := analysis.AnalyzeSALifecycle(g, opts)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleCompliance(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.ComplianceOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
		IncludeCloud:  params.IncludeCloud,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	frameworkParam := r.URL.Query().Get("frameworks")
	if frameworkParam != "" {
		frameworks := strings.Split(frameworkParam, ",")
		for _, fw := range frameworks {
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
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleIdentityChain(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	params.IncludeCloud = true

	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.IdentityChainOptions{
		Namespace:    params.Namespace,
		WorkloadRef:  params.Workload,
		IncludeCloud: true,
		MaxDepth:     10,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	outputFormat := r.URL.Query().Get("format")
	if outputFormat == "dot" || outputFormat == "mermaid" || outputFormat == "all" {
		opts.OutputFormat = outputFormat
	}

	result := analysis.AnalyzeIdentityChains(g, opts)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleGroupAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.GroupAnalysisOptions{
		Namespace:     params.Namespace,
		IncludeSystem: params.IncludeSystem,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	result := analysis.AnalyzeGroups(g, opts)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleUsageAnalysis(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	opts := analysis.UsageAnalysisOptions{
		Namespace:     params.Namespace,
		IncludeSystem: params.IncludeSystem,
		StaleDays:     30,
	}
	if params.AllNamespaces {
		opts.Namespace = ""
	}

	staleDaysParam := r.URL.Query().Get("stale_days")
	if staleDaysParam != "" {
		if days, err := strconv.Atoi(staleDaysParam); err == nil {
			opts.StaleDays = days
		}
	}

	result := analysis.AnalyzeUsage(g, opts)
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleRemediate(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet && r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET and POST are allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	rbacOpts := analysis.RBACAuditOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		rbacOpts.Namespace = ""
	}
	rbacResult := analysis.RunRBACAudit(g, rbacOpts)

	podSecOpts := analysis.PodSecurityOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		podSecOpts.Namespace = ""
	}
	podSecResult := analysis.RunPodSecurityAudit(g, podSecOpts)

	netPolOpts := analysis.NetworkPolicyOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		netPolOpts.Namespace = ""
	}
	netPolResult := analysis.RunNetworkPolicyAudit(g, netPolOpts)

	fixes := generateFixes(rbacResult, podSecResult, netPolResult, params.Severity)

	s.writeJSON(w, http.StatusOK, fixes)
}

func generateFixes(rbac *analysis.RBACAuditResult, podSec *analysis.PodSecurityResult, netPol *analysis.NetworkPolicyResult, severity string) map[string]interface{} {
	fixes := map[string]interface{}{
		"rbac_fixes":          []interface{}{},
		"pod_security_fixes":  []interface{}{},
		"network_policy_fixes": []interface{}{},
		"summary": map[string]int{
			"total_fixes": 0,
		},
	}

	return fixes
}

func (s *Server) handleSnapshot(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	rbacOpts := analysis.RBACAuditOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		rbacOpts.Namespace = ""
	}
	rbacResult := analysis.RunRBACAudit(g, rbacOpts)

	podSecOpts := analysis.PodSecurityOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		podSecOpts.Namespace = ""
	}
	podSecResult := analysis.RunPodSecurityAudit(g, podSecOpts)

	netPolOpts := analysis.NetworkPolicyOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		netPolOpts.Namespace = ""
	}
	netPolResult := analysis.RunNetworkPolicyAudit(g, netPolOpts)

	var cloudFindings []analysis.CloudIAMFinding
	if params.IncludeCloud {
		cloudResult := analysis.AnalyzeCloudIAM(g)
		cloudFindings = cloudResult.Findings
	}

	snapshot := map[string]interface{}{
		"timestamp":               time.Now().UTC().Format(time.RFC3339),
		"rbac_findings":           rbacResult.Findings,
		"pod_security_findings":   podSecResult.Findings,
		"network_policy_findings": netPolResult.Findings,
		"cloud_findings":          cloudFindings,
	}

	s.writeJSON(w, http.StatusOK, snapshot)
}

func (s *Server) handleDiff(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only POST is allowed")
		return
	}

	var baseline struct {
		RBACFindings   []analysis.RBACFinding          `json:"rbac_findings"`
		PodSecFindings []analysis.PodSecurityFinding   `json:"pod_security_findings"`
		NetPolFindings []analysis.NetworkPolicyFinding `json:"network_policy_findings"`
		CloudFindings  []analysis.CloudIAMFinding      `json:"cloud_findings"`
	}

	if err := json.NewDecoder(r.Body).Decode(&baseline); err != nil {
		s.writeError(w, http.StatusBadRequest, "INVALID_JSON", "Failed to parse baseline JSON")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 3*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	rbacOpts := analysis.RBACAuditOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		rbacOpts.Namespace = ""
	}
	rbacResult := analysis.RunRBACAudit(g, rbacOpts)

	podSecOpts := analysis.PodSecurityOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		podSecOpts.Namespace = ""
	}
	podSecResult := analysis.RunPodSecurityAudit(g, podSecOpts)

	netPolOpts := analysis.NetworkPolicyOptions{
		IncludeSystem: params.IncludeSystem,
		Namespace:     params.Namespace,
	}
	if params.AllNamespaces {
		netPolOpts.Namespace = ""
	}
	netPolResult := analysis.RunNetworkPolicyAudit(g, netPolOpts)

	var cloudFindings []analysis.CloudIAMFinding
	if params.IncludeCloud {
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
	s.writeJSON(w, http.StatusOK, result)
}

func (s *Server) handleDocsRedirect(w http.ResponseWriter, r *http.Request) {
	http.Redirect(w, r, "/swagger/", http.StatusMovedPermanently)
}

func getFirstNonEmpty(values ...string) string {
	for _, v := range values {
		if v != "" {
			return v
		}
	}
	return ""
}

func (s *Server) handleSmartScan(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		s.writeError(w, http.StatusMethodNotAllowed, "METHOD_NOT_ALLOWED", "Only GET is allowed")
		return
	}

	ctx, cancel := context.WithTimeout(r.Context(), 5*time.Minute)
	defer cancel()

	params := parseQueryParams(r)
	g, err := s.collectGraph(ctx, params)
	if err != nil {
		s.writeError(w, http.StatusInternalServerError, "COLLECTION_FAILED", err.Error())
		return
	}

	result := s.runSmartScan(g, params)
	s.writeJSON(w, http.StatusOK, result)
}

type SmartScanResult struct {
	ClusterInfo      ClusterDetection                  `json:"cluster_info"`
	PlatformInfo     *analysis.PlatformDetectionResult `json:"platform_info,omitempty"`
	ExecutedScans    []string                          `json:"executed_scans"`
	IdentityRisks    *analysis.IdentityRiskResult      `json:"identity_risks,omitempty"`
	RBACFindings     []analysis.RBACFinding            `json:"rbac_findings,omitempty"`
	ExploitablePerms *analysis.ExploitablePermResult   `json:"exploitable_permissions,omitempty"`
	AttackPaths      []*analysis.AttackPath            `json:"attack_paths,omitempty"`
	OpenShiftAudit   *analysis.OpenShiftAuditResult    `json:"openshift_audit,omitempty"`
	PodSecIssues     []analysis.PodSecurityFinding     `json:"pod_security_issues,omitempty"`
	CloudFindings    []analysis.CloudIAMFinding        `json:"cloud_findings,omitempty"`
	PlatformChecks   *analysis.PlatformCheckResult     `json:"platform_checks,omitempty"`
	Compliance       *analysis.ComplianceResult        `json:"compliance,omitempty"`
	Summary          SmartScanSummary                  `json:"summary"`
}

type ClusterDetection struct {
	IsOpenShift          bool     `json:"is_openshift"`
	OpenShiftVersion     string   `json:"openshift_version,omitempty"`
	HasAWSIdentities     bool     `json:"has_aws_identities"`
	HasGCPIdentities     bool     `json:"has_gcp_identities"`
	HasAzureIdentities   bool     `json:"has_azure_identities"`
	TotalNamespaces      int      `json:"total_namespaces"`
	TotalWorkloads       int      `json:"total_workloads"`
	TotalServiceAccounts int      `json:"total_service_accounts"`
	DetectedFeatures     []string `json:"detected_features"`
}

type SmartScanSummary struct {
	TotalFindings      int      `json:"total_findings"`
	CriticalCount      int      `json:"critical_count"`
	HighCount          int      `json:"high_count"`
	MediumCount        int      `json:"medium_count"`
	LowCount           int      `json:"low_count"`
	RiskScore          int      `json:"risk_score"`
	OverallRiskLevel   string   `json:"overall_risk_level"`
	TopRecommendations []string `json:"top_recommendations"`
}

func (s *Server) runSmartScan(g *graph.Graph, params QueryParams) *SmartScanResult {
	result := &SmartScanResult{
		ExecutedScans: []string{},
	}

	detection := s.detectClusterFeatures(g)
	result.ClusterInfo = detection

	result.ExecutedScans = append(result.ExecutedScans, "platform-detection")
	platformResult := analysis.DetectPlatform(g)
	result.PlatformInfo = platformResult

	result.ExecutedScans = append(result.ExecutedScans, "exploitable-permissions")
	exploitResult := analysis.AnalyzeExploitablePermissions(g, platformResult)
	result.ExploitablePerms = exploitResult

	result.ExecutedScans = append(result.ExecutedScans, "platform-checks")
	platformChecks := analysis.RunPlatformChecks(g, platformResult)
	result.PlatformChecks = platformChecks

	result.ExecutedScans = append(result.ExecutedScans, "identity-risk")
	riskResult := analysis.CalculateIdentityRisk(g, analysis.IdentityRiskOptions{
		TopN: 20,
	})
	result.IdentityRisks = riskResult

	result.ExecutedScans = append(result.ExecutedScans, "rbac-audit")
	rbacResult := analysis.RunRBACAudit(g, analysis.RBACAuditOptions{
		IncludeSystem: params.IncludeSystem,
	})
	result.RBACFindings = rbacResult.Findings

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

	result.ExecutedScans = append(result.ExecutedScans, "pod-security")
	podSecResult := analysis.RunPodSecurityAudit(g, analysis.PodSecurityOptions{
		IncludeSystem: params.IncludeSystem,
	})
	result.PodSecIssues = podSecResult.Findings

	if detection.IsOpenShift {
		result.ExecutedScans = append(result.ExecutedScans, "openshift-audit")
		osResult := analysis.RunOpenShiftAudit(g, analysis.OpenShiftAuditOptions{
			IncludeSystem: params.IncludeSystem,
		})
		result.OpenShiftAudit = osResult
	}

	if detection.HasAWSIdentities || detection.HasGCPIdentities || detection.HasAzureIdentities {
		result.ExecutedScans = append(result.ExecutedScans, "cloud-audit")
		cloudResult := analysis.AnalyzeCloudIAM(g)
		result.CloudFindings = cloudResult.Findings
	}

	result.ExecutedScans = append(result.ExecutedScans, "compliance")
	complianceResult := analysis.RunComplianceAnalysis(g, analysis.ComplianceOptions{
		IncludeSystem: params.IncludeSystem,
		IncludeCloud:  detection.HasAWSIdentities || detection.HasGCPIdentities || detection.HasAzureIdentities,
	})
	result.Compliance = complianceResult

	result.Summary = s.calculateSmartScanSummary(result)

	return result
}

func (s *Server) detectClusterFeatures(g *graph.Graph) ClusterDetection {
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
	}
	if detection.HasGCPIdentities {
		detection.DetectedFeatures = append(detection.DetectedFeatures, "GCP Workload Identity")
	}
	if detection.HasAzureIdentities {
		detection.DetectedFeatures = append(detection.DetectedFeatures, "Azure Managed Identity")
	}

	namespaces := make(map[string]bool)
	for _, node := range g.GetNodesByType(graph.NodeWorkload) {
		namespaces[node.Namespace] = true
	}
	detection.TotalNamespaces = len(namespaces)
	detection.TotalWorkloads = len(g.GetNodesByType(graph.NodeWorkload))
	detection.TotalServiceAccounts = len(g.GetNodesByType(graph.NodeServiceAccount))

	return detection
}

func (s *Server) calculateSmartScanSummary(result *SmartScanResult) SmartScanSummary {
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

	for _, f := range result.PodSecIssues {
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

func (s *Server) ListenAndServe(host string, port int) error {
	s.httpServer.Addr = fmt.Sprintf("%s:%d", host, port)
	return s.httpServer.ListenAndServe()
}

func NewServerSimple(kubeconfig, context string) *Server {
	return NewServer(Config{
		Kubeconfig:    kubeconfig,
		Context:       context,
		EnableSwagger: true,
		EnableCORS:    true,
	})
}
