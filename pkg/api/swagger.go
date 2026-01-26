package api

import (
	"net/http"
)

func (s *Server) handleSwaggerJSON(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "application/json")
	w.Write([]byte(OpenAPISpec))
}

func (s *Server) handleSwaggerUI(w http.ResponseWriter, r *http.Request) {
	w.Header().Set("Content-Type", "text/html")
	w.Write([]byte(SwaggerUIHTML))
}

const OpenAPISpec = `{
  "openapi": "3.0.3",
  "info": {
    "title": "Identity Chain API",
    "description": "Kubernetes Identity & Blast Radius Analyzer API. Analyze RBAC, cloud IAM, and security posture for Kubernetes and OpenShift clusters.",
    "version": "1.0.0",
    "contact": {
      "name": "Identity Chain",
      "url": "https://github.com/nelssec/identity-chain"
    },
    "license": {
      "name": "Apache 2.0",
      "url": "https://www.apache.org/licenses/LICENSE-2.0"
    }
  },
  "servers": [
    {
      "url": "/api/v1",
      "description": "API v1"
    }
  ],
  "tags": [
    {
      "name": "Health",
      "description": "Health and readiness endpoints"
    },
    {
      "name": "Scan",
      "description": "Cluster scanning and graph operations"
    },
    {
      "name": "Blast Radius",
      "description": "Blast radius analysis for workloads"
    },
    {
      "name": "Attack Paths",
      "description": "Attack path and privilege escalation analysis"
    },
    {
      "name": "RBAC",
      "description": "RBAC audit and analysis"
    },
    {
      "name": "Pod Security",
      "description": "Pod security standards analysis"
    },
    {
      "name": "Network Policy",
      "description": "Network policy analysis"
    },
    {
      "name": "Cloud IAM",
      "description": "Cloud identity and access management"
    },
    {
      "name": "OpenShift",
      "description": "OpenShift-specific security analysis"
    },
    {
      "name": "Identity Risk",
      "description": "Identity risk scoring and analysis"
    },
    {
      "name": "Remediation",
      "description": "Auto-remediation and fixes"
    },
    {
      "name": "Comparison",
      "description": "Snapshot and diff operations"
    },
    {
      "name": "Smart Scan",
      "description": "Intelligent auto-detection scanning"
    },
    {
      "name": "Compliance",
      "description": "Compliance framework mapping and analysis"
    }
  ],
  "paths": {
    "/health": {
      "get": {
        "tags": ["Health"],
        "summary": "Health check",
        "description": "Returns the health status of the API server",
        "operationId": "getHealth",
        "responses": {
          "200": {
            "description": "Server is healthy",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HealthResponse"
                }
              }
            }
          }
        }
      }
    },
    "/ready": {
      "get": {
        "tags": ["Health"],
        "summary": "Readiness check",
        "description": "Checks if the server can connect to the Kubernetes cluster",
        "operationId": "getReady",
        "responses": {
          "200": {
            "description": "Server is ready",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/HealthResponse"
                }
              }
            }
          },
          "503": {
            "description": "Server is not ready",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ErrorResponse"
                }
              }
            }
          }
        }
      }
    },
    "/scan": {
      "get": {
        "tags": ["Scan"],
        "summary": "Scan cluster",
        "description": "Scan the cluster and return statistics about identities and resources",
        "operationId": "scanCluster",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {"$ref": "#/components/parameters/includeCloud"}
        ],
        "responses": {
          "200": {
            "description": "Scan results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ScanResponse"
                }
              }
            }
          }
        }
      }
    },
    "/graph": {
      "get": {
        "tags": ["Scan"],
        "summary": "Get identity graph",
        "description": "Returns the full identity graph with nodes and edges",
        "operationId": "getGraph",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {"$ref": "#/components/parameters/includeCloud"}
        ],
        "responses": {
          "200": {
            "description": "Identity graph",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/GraphResponse"
                }
              }
            }
          }
        }
      }
    },
    "/blast": {
      "get": {
        "tags": ["Blast Radius"],
        "summary": "Analyze blast radius for all workloads",
        "description": "Calculate blast radius for all workloads in the cluster",
        "operationId": "getBlastAll",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {"$ref": "#/components/parameters/includeCloud"}
        ],
        "responses": {
          "200": {
            "description": "Blast radius results for all workloads",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/BlastResponse"
                }
              }
            }
          }
        }
      }
    },
    "/blast/workload": {
      "get": {
        "tags": ["Blast Radius"],
        "summary": "Analyze blast radius for a specific workload",
        "description": "Calculate blast radius for a single workload",
        "operationId": "getBlastWorkload",
        "parameters": [
          {
            "name": "workload",
            "in": "query",
            "required": true,
            "description": "Workload reference (e.g., deployment/api-server, pod/mypod)",
            "schema": {
              "type": "string"
            }
          },
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/includeCloud"}
        ],
        "responses": {
          "200": {
            "description": "Blast radius result",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/BlastResultResponse"
                }
              }
            }
          },
          "404": {
            "description": "Workload not found",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ErrorResponse"
                }
              }
            }
          }
        }
      }
    },
    "/attack-paths": {
      "get": {
        "tags": ["Attack Paths"],
        "summary": "Find attack paths",
        "description": "Identify potential attack paths through the cluster",
        "operationId": "getAttackPaths",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {"$ref": "#/components/parameters/includeCloud"}
        ],
        "responses": {
          "200": {
            "description": "Attack paths",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/AttackPathResponse"
                }
              }
            }
          }
        }
      }
    },
    "/privesc": {
      "get": {
        "tags": ["Attack Paths"],
        "summary": "Find privilege escalation paths",
        "description": "Identify privilege escalation vulnerabilities",
        "operationId": "getPrivesc",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"}
        ],
        "responses": {
          "200": {
            "description": "Privilege escalation paths",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/PrivescResponse"
                }
              }
            }
          }
        }
      }
    },
    "/rbac/audit": {
      "get": {
        "tags": ["RBAC"],
        "summary": "Run RBAC audit",
        "description": "Comprehensive security audit of RBAC configuration",
        "operationId": "getRBACAudit",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {
            "name": "checks",
            "in": "query",
            "description": "Comma-separated list of check IDs to run",
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "skip_checks",
            "in": "query",
            "description": "Comma-separated list of check IDs to skip",
            "schema": {
              "type": "string"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "RBAC audit results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/RBACAuditResponse"
                }
              }
            }
          }
        }
      }
    },
    "/rbac/whocan": {
      "get": {
        "tags": ["RBAC"],
        "summary": "Find who can perform an action",
        "description": "Find all subjects that can perform a specific verb on a resource",
        "operationId": "getWhocan",
        "parameters": [
          {
            "name": "verb",
            "in": "query",
            "required": true,
            "description": "The verb to check (get, list, create, delete, etc.)",
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "resource",
            "in": "query",
            "required": true,
            "description": "The resource to check (pods, secrets, deployments, etc.)",
            "schema": {
              "type": "string"
            }
          },
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"}
        ],
        "responses": {
          "200": {
            "description": "Subjects that can perform the action",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/WhocanResponse"
                }
              }
            }
          }
        }
      }
    },
    "/rbac/whatcan": {
      "get": {
        "tags": ["RBAC"],
        "summary": "Show what a service account can do",
        "description": "List all permissions for a service account",
        "operationId": "getWhatcan",
        "parameters": [
          {
            "name": "service_account",
            "in": "query",
            "required": true,
            "description": "Service account name",
            "schema": {
              "type": "string"
            }
          },
          {"$ref": "#/components/parameters/namespace"}
        ],
        "responses": {
          "200": {
            "description": "Service account permissions",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/WhatcanResponse"
                }
              }
            }
          }
        }
      }
    },
    "/pod-security": {
      "get": {
        "tags": ["Pod Security"],
        "summary": "Run pod security audit",
        "description": "Analyze workloads for pod security standards violations",
        "operationId": "getPodSecurity",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"}
        ],
        "responses": {
          "200": {
            "description": "Pod security audit results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/PodSecurityResponse"
                }
              }
            }
          }
        }
      }
    },
    "/network-policy": {
      "get": {
        "tags": ["Network Policy"],
        "summary": "Run network policy audit",
        "description": "Analyze network policies and identify gaps",
        "operationId": "getNetworkPolicy",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"}
        ],
        "responses": {
          "200": {
            "description": "Network policy audit results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/NetworkPolicyResponse"
                }
              }
            }
          }
        }
      }
    },
    "/cloud/audit": {
      "get": {
        "tags": ["Cloud IAM"],
        "summary": "Run cloud IAM audit",
        "description": "Analyze cloud IAM roles for security issues",
        "operationId": "getCloudAudit",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"}
        ],
        "responses": {
          "200": {
            "description": "Cloud IAM audit results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/CloudAuditResponse"
                }
              }
            }
          }
        }
      }
    },
    "/cloud/identity": {
      "get": {
        "tags": ["Cloud IAM"],
        "summary": "List cloud identity bindings",
        "description": "Show service accounts with cloud identity bindings",
        "operationId": "getCloudIdentity",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"}
        ],
        "responses": {
          "200": {
            "description": "Cloud identity bindings",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/CloudIdentityResponse"
                }
              }
            }
          }
        }
      }
    },
    "/openshift/audit": {
      "get": {
        "tags": ["OpenShift"],
        "summary": "Run OpenShift security audit",
        "description": "Comprehensive security audit for OpenShift clusters",
        "operationId": "getOpenShiftAudit",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"}
        ],
        "responses": {
          "200": {
            "description": "OpenShift audit results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/OpenShiftAuditResponse"
                }
              }
            }
          },
          "400": {
            "description": "Not an OpenShift cluster",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ErrorResponse"
                }
              }
            }
          }
        }
      }
    },
    "/openshift/scc": {
      "get": {
        "tags": ["OpenShift"],
        "summary": "Analyze SCCs",
        "description": "Analyze Security Context Constraints",
        "operationId": "getSCCAnalysis",
        "parameters": [
          {"$ref": "#/components/parameters/includeSystem"}
        ],
        "responses": {
          "200": {
            "description": "SCC analysis results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/SCCAnalysisResponse"
                }
              }
            }
          }
        }
      }
    },
    "/openshift/scc/simulate": {
      "get": {
        "tags": ["OpenShift"],
        "summary": "Simulate SCC selection",
        "description": "Determine which SCC a workload would use",
        "operationId": "getSCCSimulate",
        "parameters": [
          {
            "name": "workload",
            "in": "query",
            "required": true,
            "description": "Workload reference",
            "schema": {
              "type": "string"
            }
          },
          {"$ref": "#/components/parameters/namespace"}
        ],
        "responses": {
          "200": {
            "description": "SCC simulation results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/SCCSimulateResponse"
                }
              }
            }
          }
        }
      }
    },
    "/identity/risk": {
      "get": {
        "tags": ["Identity Risk"],
        "summary": "Calculate identity risk scores",
        "description": "Calculate comprehensive risk scores for all service accounts",
        "operationId": "getIdentityRisk",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {"$ref": "#/components/parameters/includeCloud"},
          {
            "name": "top",
            "in": "query",
            "description": "Number of top risky identities to return",
            "schema": {
              "type": "integer",
              "default": 10
            }
          },
          {
            "name": "min_score",
            "in": "query",
            "description": "Minimum risk score threshold",
            "schema": {
              "type": "integer"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Identity risk scores",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/IdentityRiskResponse"
                }
              }
            }
          }
        }
      }
    },
    "/identity/lifecycle": {
      "get": {
        "tags": ["Identity Risk"],
        "summary": "Analyze service account lifecycle",
        "description": "Find orphaned or stale service accounts",
        "operationId": "getSALifecycle",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"}
        ],
        "responses": {
          "200": {
            "description": "Service account lifecycle analysis",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/SALifecycleResponse"
                }
              }
            }
          }
        }
      }
    },
    "/compliance": {
      "get": {
        "tags": ["Compliance"],
        "summary": "Run compliance framework analysis",
        "description": "Map security findings to compliance frameworks including CIS Kubernetes Benchmark, NSA/CISA Kubernetes Hardening Guide, NIST 800-53, SOC2, and PCI-DSS. Returns compliance scores per framework and section with specific control gaps.",
        "operationId": "getCompliance",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {"$ref": "#/components/parameters/includeCloud"},
          {
            "name": "frameworks",
            "in": "query",
            "description": "Comma-separated list of frameworks to analyze (CIS, NSA_CISA, NIST, SOC2, PCIDSS). If not specified, all frameworks are analyzed.",
            "schema": {
              "type": "string",
              "example": "CIS,NIST,SOC2"
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Compliance analysis results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ComplianceResponse"
                }
              }
            }
          }
        }
      }
    },
    "/identity/usage": {
      "get": {
        "tags": ["Identity Risk"],
        "summary": "Analyze identity usage and over-provisioning",
        "description": "Detect unused service accounts, orphaned identities, over-provisioned accounts, and stale identities. Provides right-sizing recommendations to reduce attack surface.",
        "operationId": "getUsageAnalysis",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {
            "name": "stale_days",
            "in": "query",
            "description": "Number of days to consider an identity stale (default: 30)",
            "schema": {
              "type": "integer",
              "default": 30
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Usage analysis results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/UsageAnalysisResponse"
                }
              }
            }
          }
        }
      }
    },
    "/identity/groups": {
      "get": {
        "tags": ["Identity Risk"],
        "summary": "Analyze group permissions and nested access",
        "description": "Analyze RBAC group permissions, OIDC/LDAP group mappings, nested permission paths, and privilege escalation vectors through groups. Identifies high-risk groups with cluster-admin or secrets access.",
        "operationId": "getGroupAnalysis",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"}
        ],
        "responses": {
          "200": {
            "description": "Group analysis results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/GroupAnalysisResponse"
                }
              }
            }
          }
        }
      }
    },
    "/identity/chain": {
      "get": {
        "tags": ["Identity Risk"],
        "summary": "Trace identity chains from workloads to cloud resources",
        "description": "Analyze the complete identity chain from workloads through service accounts, RBAC roles, and cloud IAM roles to cloud resources. Provides full visibility into Pod → SA → IAM Role → Cloud Resources chains, cross-account role assumptions, trust relationships, and effective permissions calculation. Supports DOT and Mermaid output for visualization.",
        "operationId": "getIdentityChain",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {
            "name": "workload",
            "in": "query",
            "description": "Specific workload to trace (e.g., deployment/api-server). If not specified, traces all workloads.",
            "schema": {
              "type": "string"
            }
          },
          {
            "name": "format",
            "in": "query",
            "description": "Output format for visualization: dot (Graphviz), mermaid, or all",
            "schema": {
              "type": "string",
              "enum": ["dot", "mermaid", "all"]
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Identity chain analysis results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/IdentityChainResponse"
                }
              }
            }
          }
        }
      }
    },
    "/remediate": {
      "get": {
        "tags": ["Remediation"],
        "summary": "Generate remediation manifests",
        "description": "Generate Kubernetes manifests to fix security findings",
        "operationId": "getRemediate",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {
            "name": "severity",
            "in": "query",
            "description": "Minimum severity to fix (critical, high, medium, low)",
            "schema": {
              "type": "string",
              "enum": ["critical", "high", "medium", "low"]
            }
          }
        ],
        "responses": {
          "200": {
            "description": "Remediation manifests",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/RemediateResponse"
                }
              }
            }
          }
        }
      }
    },
    "/snapshot": {
      "get": {
        "tags": ["Comparison"],
        "summary": "Create security snapshot",
        "description": "Create a snapshot of current security findings",
        "operationId": "getSnapshot",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {"$ref": "#/components/parameters/includeCloud"}
        ],
        "responses": {
          "200": {
            "description": "Security snapshot",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/SnapshotResponse"
                }
              }
            }
          }
        }
      }
    },
    "/diff": {
      "post": {
        "tags": ["Comparison"],
        "summary": "Compare with baseline",
        "description": "Compare current findings against a baseline snapshot",
        "operationId": "postDiff",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeCloud"}
        ],
        "requestBody": {
          "description": "Baseline snapshot to compare against",
          "required": true,
          "content": {
            "application/json": {
              "schema": {
                "$ref": "#/components/schemas/SnapshotResponse"
              }
            }
          }
        },
        "responses": {
          "200": {
            "description": "Diff results",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/DiffResponse"
                }
              }
            }
          }
        }
      }
    },
    "/smart-scan": {
      "get": {
        "tags": ["Smart Scan"],
        "summary": "Intelligent auto-detection scan",
        "description": "Run an intelligent scan that automatically detects cluster type (Kubernetes/OpenShift), cloud identity bindings, and runs all applicable security checks. This is the recommended endpoint for comprehensive security analysis.",
        "operationId": "getSmartScan",
        "parameters": [
          {"$ref": "#/components/parameters/namespace"},
          {"$ref": "#/components/parameters/allNamespaces"},
          {"$ref": "#/components/parameters/includeSystem"},
          {"$ref": "#/components/parameters/includeCloud"}
        ],
        "responses": {
          "200": {
            "description": "Smart scan results with cluster detection, identity risks, RBAC findings, attack paths, and recommendations",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/SmartScanResponse"
                }
              }
            }
          },
          "500": {
            "description": "Scan failed",
            "content": {
              "application/json": {
                "schema": {
                  "$ref": "#/components/schemas/ErrorResponse"
                }
              }
            }
          }
        }
      }
    }
  },
  "components": {
    "parameters": {
      "namespace": {
        "name": "namespace",
        "in": "query",
        "description": "Kubernetes namespace to analyze",
        "schema": {
          "type": "string",
          "default": "default"
        }
      },
      "allNamespaces": {
        "name": "all_namespaces",
        "in": "query",
        "description": "Scan all namespaces",
        "schema": {
          "type": "boolean",
          "default": false
        }
      },
      "includeSystem": {
        "name": "include_system",
        "in": "query",
        "description": "Include system namespaces (kube-system, etc.)",
        "schema": {
          "type": "boolean",
          "default": false
        }
      },
      "includeCloud": {
        "name": "include_cloud",
        "in": "query",
        "description": "Include cloud IAM analysis",
        "schema": {
          "type": "boolean",
          "default": false
        }
      }
    },
    "schemas": {
      "APIResponse": {
        "type": "object",
        "properties": {
          "success": {
            "type": "boolean"
          },
          "data": {
            "type": "object"
          },
          "error": {
            "$ref": "#/components/schemas/APIError"
          },
          "meta": {
            "$ref": "#/components/schemas/APIMeta"
          }
        }
      },
      "APIError": {
        "type": "object",
        "properties": {
          "code": {
            "type": "string"
          },
          "message": {
            "type": "string"
          },
          "details": {
            "type": "string"
          }
        }
      },
      "APIMeta": {
        "type": "object",
        "properties": {
          "api_version": {
            "type": "string"
          },
          "request_id": {
            "type": "string"
          },
          "duration": {
            "type": "string"
          }
        }
      },
      "HealthResponse": {
        "type": "object",
        "properties": {
          "status": {
            "type": "string",
            "enum": ["healthy", "ready"]
          }
        }
      },
      "ErrorResponse": {
        "allOf": [
          {"$ref": "#/components/schemas/APIResponse"},
          {
            "type": "object",
            "properties": {
              "success": {
                "type": "boolean",
                "example": false
              }
            }
          }
        ]
      },
      "ScanResponse": {
        "type": "object",
        "properties": {
          "total_nodes": {"type": "integer"},
          "total_edges": {"type": "integer"},
          "workloads": {"type": "integer"},
          "service_accounts": {"type": "integer"},
          "roles": {"type": "integer"},
          "cloud_roles": {"type": "integer"}
        }
      },
      "GraphResponse": {
        "type": "object",
        "properties": {
          "nodes": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/Node"}
          },
          "edges": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/Edge"}
          },
          "stats": {"$ref": "#/components/schemas/ScanResponse"}
        }
      },
      "Node": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "type": {"type": "string"},
          "name": {"type": "string"},
          "namespace": {"type": "string"}
        }
      },
      "Edge": {
        "type": "object",
        "properties": {
          "from": {"type": "string"},
          "to": {"type": "string"},
          "type": {"type": "string"}
        }
      },
      "BlastResponse": {
        "type": "object",
        "properties": {
          "results": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/BlastResult"}
          }
        }
      },
      "BlastResultResponse": {
        "allOf": [
          {"$ref": "#/components/schemas/APIResponse"},
          {
            "type": "object",
            "properties": {
              "data": {"$ref": "#/components/schemas/BlastResult"}
            }
          }
        ]
      },
      "BlastResult": {
        "type": "object",
        "properties": {
          "workload": {"type": "string"},
          "namespace": {"type": "string"},
          "service_account": {"type": "string"},
          "max_severity": {"type": "string"},
          "k8s_resources": {"type": "array", "items": {"type": "object"}},
          "cloud_roles": {"type": "array", "items": {"type": "object"}}
        }
      },
      "AttackPathResponse": {
        "type": "object",
        "properties": {
          "results": {"type": "array", "items": {"type": "object"}},
          "summary": {"type": "object"}
        }
      },
      "PrivescResponse": {
        "type": "object",
        "properties": {
          "paths": {"type": "array", "items": {"type": "object"}}
        }
      },
      "RBACAuditResponse": {
        "type": "object",
        "properties": {
          "findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "summary": {"type": "object"}
        }
      },
      "Finding": {
        "type": "object",
        "properties": {
          "check_id": {"type": "string"},
          "severity": {"type": "string"},
          "title": {"type": "string"},
          "description": {"type": "string"},
          "affected": {"type": "array", "items": {"type": "object"}},
          "remediation": {"type": "string"}
        }
      },
      "WhocanResponse": {
        "type": "object",
        "properties": {
          "verb": {"type": "string"},
          "resource": {"type": "string"},
          "subjects": {"type": "array", "items": {"type": "object"}}
        }
      },
      "WhatcanResponse": {
        "type": "object",
        "properties": {
          "service_account": {"type": "string"},
          "namespace": {"type": "string"},
          "permissions": {"type": "array", "items": {"type": "object"}}
        }
      },
      "PodSecurityResponse": {
        "type": "object",
        "properties": {
          "findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "summary": {"type": "object"}
        }
      },
      "NetworkPolicyResponse": {
        "type": "object",
        "properties": {
          "findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "summary": {"type": "object"}
        }
      },
      "CloudAuditResponse": {
        "type": "object",
        "properties": {
          "findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "summary": {"type": "object"}
        }
      },
      "CloudIdentityResponse": {
        "type": "object",
        "properties": {
          "identities": {"type": "array", "items": {"type": "object"}},
          "total": {"type": "integer"}
        }
      },
      "OpenShiftAuditResponse": {
        "type": "object",
        "properties": {
          "is_openshift": {"type": "boolean"},
          "scc_analysis": {"type": "object"},
          "route_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "oauth_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "build_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "project_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "rbac_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "summary": {"type": "object"}
        }
      },
      "SCCAnalysisResponse": {
        "type": "object",
        "properties": {
          "sccs": {"type": "array", "items": {"type": "object"}},
          "bindings": {"type": "array", "items": {"type": "object"}},
          "risky_bindings": {"type": "array", "items": {"type": "object"}},
          "escalation_paths": {"type": "array", "items": {"type": "object"}},
          "summary": {"type": "object"}
        }
      },
      "SCCSimulateResponse": {
        "type": "object",
        "properties": {
          "workload": {"type": "object"},
          "service_account": {"type": "object"},
          "available_sccs": {"type": "array", "items": {"type": "object"}},
          "selected_scc": {"type": "object"}
        }
      },
      "IdentityRiskResponse": {
        "type": "object",
        "properties": {
          "identities": {"type": "array", "items": {"$ref": "#/components/schemas/IdentityRisk"}},
          "top_risks": {"type": "array", "items": {"$ref": "#/components/schemas/IdentityRisk"}},
          "summary": {"type": "object"},
          "recommendations": {"type": "array", "items": {"type": "string"}}
        }
      },
      "IdentityRisk": {
        "type": "object",
        "properties": {
          "type": {"type": "string"},
          "name": {"type": "string"},
          "namespace": {"type": "string"},
          "risk_score": {"type": "integer"},
          "risk_level": {"type": "string"},
          "risk_factors": {"type": "array", "items": {"type": "object"}},
          "has_cluster_admin": {"type": "boolean"},
          "can_access_secrets": {"type": "boolean"},
          "cloud_roles": {"type": "array", "items": {"type": "string"}}
        }
      },
      "SALifecycleResponse": {
        "type": "object",
        "properties": {
          "orphaned": {"type": "array", "items": {"type": "object"}},
          "stale": {"type": "array", "items": {"type": "object"}},
          "summary": {"type": "object"}
        }
      },
      "ComplianceResponse": {
        "type": "object",
        "description": "Results from compliance framework analysis",
        "properties": {
          "frameworks": {
            "type": "array",
            "description": "Compliance results per framework",
            "items": {"$ref": "#/components/schemas/FrameworkCompliance"}
          },
          "overall_score": {
            "type": "number",
            "description": "Overall compliance score (average across frameworks)"
          },
          "critical_gaps": {
            "type": "array",
            "description": "Critical compliance gaps across all frameworks",
            "items": {"$ref": "#/components/schemas/ComplianceGap"}
          },
          "control_status": {
            "type": "object",
            "description": "Status of each control by ID",
            "additionalProperties": {"$ref": "#/components/schemas/ControlResult"}
          },
          "mapped_findings": {
            "type": "array",
            "description": "Security findings mapped to compliance controls",
            "items": {"$ref": "#/components/schemas/MappedFinding"}
          },
          "summary": {"$ref": "#/components/schemas/ComplianceSummary"},
          "recommendations": {
            "type": "array",
            "description": "Recommendations for improving compliance",
            "items": {"type": "string"}
          }
        }
      },
      "FrameworkCompliance": {
        "type": "object",
        "properties": {
          "framework": {"type": "string", "enum": ["CIS", "NSA_CISA", "NIST", "SOC2", "PCI_DSS"]},
          "name": {"type": "string", "description": "Framework full name"},
          "version": {"type": "string", "description": "Framework version"},
          "total_controls": {"type": "integer"},
          "passed_controls": {"type": "integer"},
          "failed_controls": {"type": "integer"},
          "not_applicable": {"type": "integer"},
          "compliance_percent": {"type": "number", "description": "Percentage of controls passed"},
          "section_results": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/SectionCompliance"}
          },
          "top_gaps": {
            "type": "array",
            "description": "Top 10 compliance gaps for this framework",
            "items": {"$ref": "#/components/schemas/ComplianceGap"}
          }
        }
      },
      "SectionCompliance": {
        "type": "object",
        "properties": {
          "section_id": {"type": "string"},
          "section_title": {"type": "string"},
          "total_controls": {"type": "integer"},
          "passed_controls": {"type": "integer"},
          "failed_controls": {"type": "integer"},
          "compliance_percent": {"type": "number"}
        }
      },
      "ComplianceGap": {
        "type": "object",
        "properties": {
          "framework": {"type": "string"},
          "control_id": {"type": "string"},
          "control_title": {"type": "string"},
          "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "finding": {"type": "string", "description": "Description of the finding"},
          "remediation": {"type": "string"},
          "affected_count": {"type": "integer"}
        }
      },
      "ControlResult": {
        "type": "object",
        "properties": {
          "control_id": {"type": "string"},
          "status": {"type": "string", "enum": ["passed", "failed", "not_applicable"]},
          "findings": {"type": "array", "items": {"type": "string"}},
          "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]}
        }
      },
      "MappedFinding": {
        "type": "object",
        "properties": {
          "check_id": {"type": "string"},
          "title": {"type": "string"},
          "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "cis_controls": {"type": "array", "items": {"type": "string"}},
          "nsa_cisa_ref": {"type": "array", "items": {"type": "string"}},
          "nist_controls": {"type": "array", "items": {"type": "string"}},
          "soc2_controls": {"type": "array", "items": {"type": "string"}},
          "pci_dss_reqs": {"type": "array", "items": {"type": "string"}}
        }
      },
      "ComplianceSummary": {
        "type": "object",
        "properties": {
          "total_frameworks": {"type": "integer"},
          "average_compliance": {"type": "number"},
          "critical_gaps_count": {"type": "integer"},
          "high_gaps_count": {"type": "integer"},
          "total_findings": {"type": "integer"},
          "by_framework": {
            "type": "object",
            "description": "Compliance percentage by framework",
            "additionalProperties": {"type": "number"}
          }
        }
      },
      "IdentityChainResponse": {
        "type": "object",
        "description": "Results from identity chain analysis",
        "properties": {
          "chains": {
            "type": "array",
            "description": "All traced identity chains",
            "items": {"$ref": "#/components/schemas/IdentityChain"}
          },
          "total_workloads": {"type": "integer"},
          "chains_with_cloud_access": {"type": "integer"},
          "cross_account_chains": {"type": "integer"},
          "high_risk_chains": {
            "type": "array",
            "description": "Chains with risk score >= 70",
            "items": {"$ref": "#/components/schemas/IdentityChain"}
          },
          "summary": {"$ref": "#/components/schemas/IdentityChainSummary"},
          "dot_output": {
            "type": "string",
            "description": "Graphviz DOT format output for visualization"
          },
          "mermaid_output": {
            "type": "string",
            "description": "Mermaid diagram format output for visualization"
          }
        }
      },
      "IdentityChain": {
        "type": "object",
        "properties": {
          "workload_id": {"type": "string"},
          "workload_name": {"type": "string"},
          "workload_namespace": {"type": "string"},
          "workload_kind": {"type": "string"},
          "service_account": {"$ref": "#/components/schemas/ChainServiceAccount"},
          "k8s_roles": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/ChainK8sRole"}
          },
          "cloud_roles": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/ChainCloudRole"}
          },
          "cloud_resources": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/ChainCloudResource"}
          },
          "effective_permissions": {"$ref": "#/components/schemas/EffectivePermissions"},
          "risk_score": {"type": "integer"},
          "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "chain_depth": {"type": "integer"},
          "has_cloud_access": {"type": "boolean"},
          "is_cross_account": {"type": "boolean"},
          "trust_chain": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/TrustRelationship"}
          }
        }
      },
      "ChainServiceAccount": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "namespace": {"type": "string"},
          "automount_token": {"type": "boolean"},
          "cloud_role_arn": {"type": "string"},
          "gcp_service_account": {"type": "string"},
          "azure_managed_id": {"type": "string"},
          "cloud_provider": {"type": "string", "enum": ["aws", "gcp", "azure"]}
        }
      },
      "ChainK8sRole": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "namespace": {"type": "string"},
          "is_cluster_role": {"type": "boolean"},
          "via_binding": {"type": "string"},
          "rules": {"type": "array", "items": {"type": "object"}}
        }
      },
      "ChainCloudRole": {
        "type": "object",
        "properties": {
          "provider": {"type": "string"},
          "role_arn": {"type": "string"},
          "role_name": {"type": "string"},
          "account_id": {"type": "string"},
          "is_admin": {"type": "boolean"},
          "policies": {"type": "array", "items": {"type": "object"}},
          "can_assume_roles": {"type": "array", "items": {"type": "string"}}
        }
      },
      "ChainCloudResource": {
        "type": "object",
        "properties": {
          "provider": {"type": "string"},
          "resource_type": {"type": "string"},
          "resource_arn": {"type": "string"},
          "resource_name": {"type": "string"},
          "access_level": {"type": "string"},
          "actions": {"type": "array", "items": {"type": "string"}}
        }
      },
      "TrustRelationship": {
        "type": "object",
        "properties": {
          "from": {"type": "string"},
          "to": {"type": "string"},
          "trust_type": {"type": "string"},
          "condition": {"type": "string"},
          "cross_account": {"type": "boolean"},
          "source_account_id": {"type": "string"},
          "target_account_id": {"type": "string"}
        }
      },
      "EffectivePermissions": {
        "type": "object",
        "properties": {
          "k8s_permissions": {"type": "array", "items": {"type": "object"}},
          "cloud_permissions": {"type": "array", "items": {"type": "object"}},
          "can_access_secrets": {"type": "boolean"},
          "has_cluster_admin": {"type": "boolean"},
          "has_cloud_admin": {"type": "boolean"}
        }
      },
      "IdentityChainSummary": {
        "type": "object",
        "properties": {
          "total_chains": {"type": "integer"},
          "chains_with_cloud_access": {"type": "integer"},
          "cross_account_chains": {"type": "integer"},
          "chains_with_admin": {"type": "integer"},
          "average_chain_depth": {"type": "number"},
          "max_chain_depth": {"type": "integer"},
          "by_cloud_provider": {
            "type": "object",
            "additionalProperties": {"type": "integer"}
          },
          "by_risk_level": {
            "type": "object",
            "additionalProperties": {"type": "integer"}
          }
        }
      },
      "GroupAnalysisResponse": {
        "type": "object",
        "description": "Results from group permission analysis",
        "properties": {
          "groups": {
            "type": "array",
            "description": "All analyzed groups",
            "items": {"$ref": "#/components/schemas/GroupInfo"}
          },
          "high_risk_groups": {
            "type": "array",
            "description": "Groups with risk score >= 70",
            "items": {"$ref": "#/components/schemas/GroupInfo"}
          },
          "oidc_group_mappings": {
            "type": "array",
            "description": "OIDC/IDP group to K8s group mappings",
            "items": {"$ref": "#/components/schemas/OIDCGroupMapping"}
          },
          "nested_permissions": {
            "type": "array",
            "description": "Permission paths through group hierarchy",
            "items": {"type": "object"}
          },
          "privilege_escalation_paths": {
            "type": "array",
            "description": "Detected privilege escalation vectors through groups",
            "items": {"$ref": "#/components/schemas/GroupPrivEscPath"}
          },
          "summary": {"$ref": "#/components/schemas/GroupAnalysisSummary"},
          "recommendations": {
            "type": "array",
            "items": {"type": "string"}
          }
        }
      },
      "GroupInfo": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "type": {"type": "string", "enum": ["system", "oidc", "ldap", "aws", "gcp", "azure", "custom"]},
          "member_count": {"type": "integer"},
          "role_bindings": {"type": "array", "items": {"type": "object"}},
          "effective_roles": {"type": "array", "items": {"type": "object"}},
          "risk_score": {"type": "integer"},
          "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "risk_factors": {"type": "array", "items": {"type": "string"}},
          "has_cluster_admin": {"type": "boolean"},
          "has_secrets_access": {"type": "boolean"},
          "namespaces": {"type": "array", "items": {"type": "string"}}
        }
      },
      "OIDCGroupMapping": {
        "type": "object",
        "properties": {
          "oidc_provider": {"type": "string"},
          "oidc_group": {"type": "string"},
          "k8s_group": {"type": "string"},
          "claim_path": {"type": "string"},
          "effective_roles": {"type": "array", "items": {"type": "string"}},
          "risk_level": {"type": "string"}
        }
      },
      "GroupPrivEscPath": {
        "type": "object",
        "properties": {
          "group": {"type": "string"},
          "escalation_path": {"type": "array", "items": {"type": "string"}},
          "target_role": {"type": "string"},
          "technique": {"type": "string"},
          "severity": {"type": "string"},
          "description": {"type": "string"}
        }
      },
      "GroupAnalysisSummary": {
        "type": "object",
        "properties": {
          "total_groups": {"type": "integer"},
          "high_risk_groups": {"type": "integer"},
          "groups_with_admin": {"type": "integer"},
          "groups_with_secrets": {"type": "integer"},
          "oidc_mappings": {"type": "integer"},
          "priv_esc_paths": {"type": "integer"},
          "total_role_bindings": {"type": "integer"},
          "by_group_type": {
            "type": "object",
            "additionalProperties": {"type": "integer"}
          },
          "by_risk_level": {
            "type": "object",
            "additionalProperties": {"type": "integer"}
          }
        }
      },
      "UsageAnalysisResponse": {
        "type": "object",
        "description": "Results from identity usage analysis",
        "properties": {
          "unused_service_accounts": {
            "type": "array",
            "description": "Service accounts with no workloads attached",
            "items": {"$ref": "#/components/schemas/UnusedServiceAccount"}
          },
          "orphaned_identities": {
            "type": "array",
            "description": "Identities with bindings but no active usage",
            "items": {"$ref": "#/components/schemas/OrphanedIdentity"}
          },
          "over_provisioned_accounts": {
            "type": "array",
            "description": "Accounts with more permissions than used",
            "items": {"$ref": "#/components/schemas/OverProvisionedAccount"}
          },
          "stale_identities": {
            "type": "array",
            "description": "Identities not used within threshold days",
            "items": {"type": "object"}
          },
          "right_sizing_recommendations": {
            "type": "array",
            "description": "Recommendations to reduce permissions",
            "items": {"$ref": "#/components/schemas/RightSizingRec"}
          },
          "summary": {"$ref": "#/components/schemas/UsageAnalysisSummary"},
          "recommendations": {
            "type": "array",
            "items": {"type": "string"}
          }
        }
      },
      "UnusedServiceAccount": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "namespace": {"type": "string"},
          "has_role_bindings": {"type": "boolean"},
          "role_bindings": {"type": "array", "items": {"type": "string"}},
          "has_cloud_role": {"type": "boolean"},
          "cloud_role_arn": {"type": "string"},
          "reason": {"type": "string"},
          "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]}
        }
      },
      "OrphanedIdentity": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "namespace": {"type": "string"},
          "type": {"type": "string"},
          "role_bindings": {"type": "array", "items": {"type": "string"}},
          "effective_roles": {"type": "array", "items": {"type": "string"}},
          "orphan_reason": {"type": "string"},
          "risk_level": {"type": "string"},
          "has_secrets_access": {"type": "boolean"},
          "has_cluster_admin": {"type": "boolean"}
        }
      },
      "OverProvisionedAccount": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "namespace": {"type": "string"},
          "type": {"type": "string"},
          "granted_permissions": {"type": "integer"},
          "used_permissions": {"type": "integer"},
          "unused_permissions": {"type": "integer"},
          "over_provision_rate": {"type": "number"},
          "roles": {"type": "array", "items": {"type": "string"}},
          "risk_level": {"type": "string"}
        }
      },
      "RightSizingRec": {
        "type": "object",
        "properties": {
          "identity": {"type": "string"},
          "namespace": {"type": "string"},
          "current_roles": {"type": "array", "items": {"type": "string"}},
          "suggested_roles": {"type": "array", "items": {"type": "string"}},
          "removable_permissions": {"type": "array", "items": {"type": "string"}},
          "impact_level": {"type": "string"},
          "reason": {"type": "string"}
        }
      },
      "UsageAnalysisSummary": {
        "type": "object",
        "properties": {
          "total_service_accounts": {"type": "integer"},
          "unused_count": {"type": "integer"},
          "orphaned_count": {"type": "integer"},
          "over_provisioned_count": {"type": "integer"},
          "stale_count": {"type": "integer"},
          "total_right_sizing_recs": {"type": "integer"},
          "by_namespace": {
            "type": "object",
            "additionalProperties": {"type": "integer"}
          },
          "high_risk_unused": {"type": "integer"},
          "avg_over_provision_rate": {"type": "number"}
        }
      },
      "RemediateResponse": {
        "type": "object",
        "properties": {
          "rbac_fixes": {"type": "array", "items": {"type": "object"}},
          "pod_security_fixes": {"type": "array", "items": {"type": "object"}},
          "network_policy_fixes": {"type": "array", "items": {"type": "object"}},
          "summary": {"type": "object"}
        }
      },
      "SnapshotResponse": {
        "type": "object",
        "properties": {
          "timestamp": {"type": "string", "format": "date-time"},
          "rbac_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "pod_security_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "network_policy_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}},
          "cloud_findings": {"type": "array", "items": {"$ref": "#/components/schemas/Finding"}}
        }
      },
      "DiffResponse": {
        "type": "object",
        "properties": {
          "new_findings": {"type": "array", "items": {"type": "object"}},
          "resolved_findings": {"type": "array", "items": {"type": "object"}},
          "unchanged_count": {"type": "integer"},
          "summary": {
            "type": "object",
            "properties": {
              "baseline_total": {"type": "integer"},
              "current_total": {"type": "integer"},
              "new_count": {"type": "integer"},
              "resolved_count": {"type": "integer"},
              "status": {"type": "string", "enum": ["improved", "degraded", "unchanged", "mixed"]}
            }
          }
        }
      },
      "SmartScanResponse": {
        "type": "object",
        "description": "Results from intelligent auto-detection scan",
        "properties": {
          "cluster_info": {
            "type": "object",
            "description": "Auto-detected cluster information",
            "properties": {
              "is_openshift": {"type": "boolean", "description": "Whether cluster is OpenShift"},
              "openshift_version": {"type": "string", "description": "OpenShift version if detected"},
              "has_aws_identities": {"type": "boolean", "description": "AWS IAM roles detected"},
              "has_gcp_identities": {"type": "boolean", "description": "GCP Workload Identity detected"},
              "has_azure_identities": {"type": "boolean", "description": "Azure Managed Identity detected"},
              "total_namespaces": {"type": "integer"},
              "total_workloads": {"type": "integer"},
              "total_service_accounts": {"type": "integer"},
              "detected_features": {"type": "array", "items": {"type": "string"}}
            }
          },
          "platform_info": {
            "$ref": "#/components/schemas/PlatformDetectionResult",
            "description": "Comprehensive platform detection including cloud provider, identity bindings, and capabilities"
          },
          "executed_scans": {
            "type": "array",
            "items": {"type": "string"},
            "description": "List of scans that were executed based on cluster detection"
          },
          "identity_risks": {
            "type": "object",
            "description": "Identity risk scoring results",
            "properties": {
              "total_identities": {"type": "integer"},
              "high_risk_count": {"type": "integer"},
              "top_risks": {"type": "array", "items": {"$ref": "#/components/schemas/IdentityRisk"}}
            }
          },
          "rbac_findings": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/RBACFinding"},
            "description": "RBAC security findings"
          },
          "exploitable_permissions": {
            "$ref": "#/components/schemas/ExploitablePermResult",
            "description": "Analysis of permissions that could be exploited for privilege escalation or lateral movement"
          },
          "attack_paths": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/AttackPath"},
            "description": "Detected attack paths"
          },
          "openshift_audit": {
            "type": "object",
            "description": "OpenShift-specific audit results (if OpenShift detected)"
          },
          "pod_security_issues": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/PodSecurityFinding"},
            "description": "Pod security findings"
          },
          "cloud_findings": {
            "type": "array",
            "items": {"type": "object"},
            "description": "Cloud IAM findings (if cloud identities detected)"
          },
          "platform_checks": {
            "$ref": "#/components/schemas/PlatformCheckResult",
            "description": "Platform-specific security checks for EKS, GKE, AKS, OpenShift, Rancher, K3s, etc."
          },
          "compliance": {
            "$ref": "#/components/schemas/ComplianceResponse",
            "description": "Compliance framework analysis results (CIS, NSA/CISA, NIST 800-53, SOC2, PCI-DSS)"
          },
          "summary": {
            "type": "object",
            "description": "Overall scan summary",
            "properties": {
              "total_findings": {"type": "integer"},
              "critical_count": {"type": "integer"},
              "high_count": {"type": "integer"},
              "medium_count": {"type": "integer"},
              "low_count": {"type": "integer"},
              "risk_score": {"type": "integer", "description": "Aggregate risk score"},
              "overall_risk_level": {"type": "string", "enum": ["LOW", "MEDIUM", "HIGH", "CRITICAL"]},
              "top_recommendations": {"type": "array", "items": {"type": "string"}}
            }
          }
        }
      },
      "PlatformDetectionResult": {
        "type": "object",
        "description": "Comprehensive platform detection results",
        "properties": {
          "primary": {
            "$ref": "#/components/schemas/PlatformInfo"
          },
          "secondary": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/PlatformInfo"}
          },
          "cloud_identities": {
            "$ref": "#/components/schemas/CloudIdentityInfo"
          },
          "capabilities": {
            "$ref": "#/components/schemas/PlatformCapabilities"
          },
          "recommended_checks": {
            "type": "array",
            "items": {"type": "string"}
          },
          "platform_specific_risks": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/PlatformRisk"}
          }
        }
      },
      "PlatformInfo": {
        "type": "object",
        "properties": {
          "platform": {"type": "string", "enum": ["kubernetes", "openshift", "rancher", "k3s", "eks", "aks", "gke", "fargate", "aci", "aca", "cloud_run", "rke2", "tanzu", "docker_ee", "microk8s", "kind", "minikube", "doks", "lke", "oke"]},
          "version": {"type": "string"},
          "cloud_provider": {"type": "string", "enum": ["aws", "azure", "gcp", "oracle", "digitalocean", "linode", "on_premises"]},
          "region": {"type": "string"},
          "account_id": {"type": "string"},
          "cluster_name": {"type": "string"},
          "is_managed": {"type": "boolean"},
          "is_serverless": {"type": "boolean"},
          "supports_irsa": {"type": "boolean"},
          "supports_workload_identity": {"type": "boolean"},
          "supports_pod_identity": {"type": "boolean"},
          "features": {"type": "array", "items": {"type": "string"}},
          "warnings": {"type": "array", "items": {"type": "string"}},
          "security_concerns": {"type": "array", "items": {"type": "string"}}
        }
      },
      "CloudIdentityInfo": {
        "type": "object",
        "properties": {
          "has_aws_irsa": {"type": "boolean"},
          "has_aws_pod_identity": {"type": "boolean"},
          "has_gcp_workload_identity": {"type": "boolean"},
          "has_azure_workload_identity": {"type": "boolean"},
          "has_azure_pod_identity": {"type": "boolean"},
          "aws_role_arns": {"type": "array", "items": {"type": "string"}},
          "gcp_service_accounts": {"type": "array", "items": {"type": "string"}},
          "azure_client_ids": {"type": "array", "items": {"type": "string"}}
        }
      },
      "PlatformCapabilities": {
        "type": "object",
        "properties": {
          "supports_network_policy": {"type": "boolean"},
          "supports_psp": {"type": "boolean"},
          "supports_psa": {"type": "boolean"},
          "supports_scc": {"type": "boolean"},
          "supports_runtime_class": {"type": "boolean"},
          "supports_gvisor": {"type": "boolean"},
          "supports_kata_containers": {"type": "boolean"},
          "supports_service_mesh": {"type": "boolean"},
          "has_istio": {"type": "boolean"},
          "has_linkerd": {"type": "boolean"},
          "has_cilium": {"type": "boolean"},
          "has_calico": {"type": "boolean"}
        }
      },
      "PlatformRisk": {
        "type": "object",
        "properties": {
          "platform": {"type": "string"},
          "category": {"type": "string"},
          "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "title": {"type": "string"},
          "description": {"type": "string"},
          "remediation": {"type": "string"}
        }
      },
      "ExploitablePermResult": {
        "type": "object",
        "description": "Results from exploitable permissions analysis",
        "properties": {
          "total_analyzed": {"type": "integer"},
          "critical_count": {"type": "integer"},
          "high_count": {"type": "integer"},
          "medium_count": {"type": "integer"},
          "low_count": {"type": "integer"},
          "findings": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/ExploitablePermission"}
          },
          "by_category": {
            "type": "object",
            "additionalProperties": {"type": "integer"}
          },
          "top_risky_subjects": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/SubjectRiskSummary"}
          }
        }
      },
      "ExploitablePermission": {
        "type": "object",
        "properties": {
          "id": {"type": "string"},
          "category": {"type": "string", "enum": ["privilege_escalation", "secret_access", "pod_execution", "pod_creation", "node_access", "rbac_manipulation", "token_theft", "cloud_escalation", "persistence", "lateral_movement", "data_exfiltration", "denial_of_service", "container_escape"]},
          "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "title": {"type": "string"},
          "description": {"type": "string"},
          "subject": {"$ref": "#/components/schemas/SubjectInfo"},
          "permission": {"$ref": "#/components/schemas/PermissionDetail"},
          "exploit_scenario": {"type": "string"},
          "remediation": {"type": "string"},
          "references": {"type": "array", "items": {"type": "string"}},
          "affected_pods": {"type": "array", "items": {"type": "string"}},
          "platform": {"type": "array", "items": {"type": "string"}}
        }
      },
      "SubjectInfo": {
        "type": "object",
        "properties": {
          "kind": {"type": "string"},
          "name": {"type": "string"},
          "namespace": {"type": "string"}
        }
      },
      "PermissionDetail": {
        "type": "object",
        "properties": {
          "verbs": {"type": "array", "items": {"type": "string"}},
          "api_groups": {"type": "array", "items": {"type": "string"}},
          "resources": {"type": "array", "items": {"type": "string"}},
          "resource_names": {"type": "array", "items": {"type": "string"}},
          "non_resource_urls": {"type": "array", "items": {"type": "string"}},
          "via_role": {"type": "string"},
          "via_binding": {"type": "string"},
          "scope": {"type": "string"}
        }
      },
      "SubjectRiskSummary": {
        "type": "object",
        "properties": {
          "subject": {"$ref": "#/components/schemas/SubjectInfo"},
          "risk_score": {"type": "integer"},
          "critical_perms": {"type": "integer"},
          "high_perms": {"type": "integer"},
          "exploit_types": {"type": "array", "items": {"type": "string"}}
        }
      },
      "PlatformCheckResult": {
        "type": "object",
        "description": "Results from platform-specific security checks",
        "properties": {
          "platform": {"type": "string"},
          "total_checks": {"type": "integer"},
          "passed_checks": {"type": "integer"},
          "failed_checks": {"type": "integer"},
          "critical_count": {"type": "integer"},
          "high_count": {"type": "integer"},
          "medium_count": {"type": "integer"},
          "low_count": {"type": "integer"},
          "findings": {
            "type": "array",
            "items": {"$ref": "#/components/schemas/PlatformCheckFinding"}
          },
          "recommendations": {"type": "array", "items": {"type": "string"}}
        }
      },
      "PlatformCheckFinding": {
        "type": "object",
        "properties": {
          "check_id": {"type": "string"},
          "platform": {"type": "string"},
          "category": {"type": "string"},
          "severity": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "title": {"type": "string"},
          "description": {"type": "string"},
          "resource": {"type": "string"},
          "namespace": {"type": "string"},
          "remediation": {"type": "string"},
          "passed": {"type": "boolean"}
        }
      },
      "IdentityRisk": {
        "type": "object",
        "properties": {
          "name": {"type": "string"},
          "namespace": {"type": "string"},
          "risk_score": {"type": "integer"},
          "risk_level": {"type": "string", "enum": ["low", "medium", "high", "critical"]},
          "risk_factors": {
            "type": "array",
            "items": {
              "type": "object",
              "properties": {
                "category": {"type": "string"},
                "description": {"type": "string"},
                "score": {"type": "integer"},
                "severity": {"type": "string"}
              }
            }
          }
        }
      }
    }
  }
}`

const SwaggerUIHTML = `<!DOCTYPE html>
<html>
<head>
  <title>Identity Chain API</title>
  <meta charset="utf-8"/>
  <meta name="viewport" content="width=device-width, initial-scale=1">
  <link rel="stylesheet" type="text/css" href="https://unpkg.com/swagger-ui-dist@5/swagger-ui.css">
  <style>
    body { margin: 0; padding: 0; }
    .swagger-ui .topbar { display: none; }
    .swagger-ui .info .title { font-size: 2em; }
  </style>
</head>
<body>
  <div id="swagger-ui"></div>
  <script src="https://unpkg.com/swagger-ui-dist@5/swagger-ui-bundle.js"></script>
  <script>
    window.onload = function() {
      SwaggerUIBundle({
        url: "/swagger.json",
        dom_id: '#swagger-ui',
        deepLinking: true,
        presets: [
          SwaggerUIBundle.presets.apis,
          SwaggerUIBundle.SwaggerUIStandalonePreset
        ],
        layout: "BaseLayout",
        defaultModelsExpandDepth: 1,
        defaultModelExpandDepth: 1,
        docExpansion: "list",
        filter: true,
        showExtensions: true,
        showCommonExtensions: true
      });
    };
  </script>
</body>
</html>`
