# Understanding Kubernetes Identity Chains and Blast Radius Analysis

When a Kubernetes workload is compromised, security teams need to answer: **"What can the attacker access?"**

This is the blast radius - the total impact of a security breach spreading through the identity chain from workload to ServiceAccount to RBAC to cloud IAM.

Whether you're running EKS, GKE, AKS, OpenShift, or vanilla Kubernetes - Identity Chain maps these relationships and calculates the blast radius.

## The Problem: Identity Sprawl in Cloud-Native Environments

Modern Kubernetes deployments have complex identity relationships:

```mermaid
graph TB
    subgraph "Kubernetes Cluster"
        W1[Pod: api-server] -->|uses| SA1[ServiceAccount: api-sa]
        W2[Pod: worker] -->|uses| SA2[ServiceAccount: worker-sa]
        W3[Pod: admin-tools] -->|uses| SA3[ServiceAccount: admin-sa]

        SA1 -->|binds to| R1[Role: api-role]
        SA2 -->|binds to| R2[ClusterRole: worker-role]
        SA3 -->|binds to| R3[ClusterRole: cluster-admin]

        R1 -->|grants| RES1[secrets in api namespace]
        R2 -->|grants| RES2[pods across cluster]
        R3 -->|grants| RES3[ALL resources]
    end

    subgraph "Cloud Provider"
        SA1 -->|IRSA| IAM1[IAM Role: api-s3-reader]
        SA2 -->|Workload Identity| IAM2[IAM Role: worker-secrets]

        IAM1 -->|allows| S3[S3 Buckets]
        IAM2 -->|allows| SM[Secrets Manager]
        IAM2 -->|allows| RDS[RDS Databases]
    end

    style W3 fill:#ff6b6b
    style R3 fill:#ff6b6b
    style RES3 fill:#ff6b6b
```

Each workload has an identity (ServiceAccount) that grants access to:
1. **Kubernetes resources** via RBAC (Roles, ClusterRoles)
2. **Cloud resources** via identity federation (IRSA, Workload Identity)

## The Identity Chain

When a pod runs in Kubernetes, it automatically receives credentials via its ServiceAccount. These credentials flow through multiple layers:

```mermaid
sequenceDiagram
    participant Pod
    participant K8sAPI as Kubernetes API
    participant RBAC as RBAC Engine
    participant Cloud as Cloud IAM
    participant Resources as Cloud Resources

    Pod->>K8sAPI: Request with SA Token
    K8sAPI->>RBAC: Check permissions
    RBAC-->>K8sAPI: Allowed/Denied
    K8sAPI-->>Pod: K8s Resource Access

    Pod->>Cloud: AssumeRoleWithWebIdentity (OIDC)
    Cloud->>Cloud: Validate OIDC Token
    Cloud-->>Pod: Temporary Cloud Credentials
    Pod->>Resources: Access S3, Secrets Manager, etc.
```

## Blast Radius: What Can an Attacker Access?

If an attacker compromises a workload, they inherit its identity. The blast radius includes everything that identity can reach:

```mermaid
graph LR
    subgraph "Compromised Workload"
        A[Attacker in Pod]
    end

    subgraph "Kubernetes Access"
        A -->|1. Read| B[Secrets]
        A -->|2. Exec into| C[Other Pods]
        A -->|3. Create| D[New Pods]
        A -->|4. Modify| E[Deployments]
    end

    subgraph "Cloud Access via IRSA"
        A -->|5. Read/Write| F[S3 Buckets]
        A -->|6. Read| G[Secrets Manager]
        A -->|7. Query| H[RDS Databases]
    end

    subgraph "Lateral Movement"
        B -->|credentials in secrets| I[Other Services]
        C -->|exec + pivot| J[More Workloads]
        G -->|cloud credentials| K[Other AWS Services]
    end

    style A fill:#ff0000,color:#fff
    style B fill:#ff6b6b
    style F fill:#ff6b6b
    style G fill:#ff6b6b
```

## Real-World Attack Scenarios

### Scenario 1: Secrets Exposure

```mermaid
flowchart TD
    A[Attacker exploits vulnerability] --> B[Gains shell in pod]
    B --> C{Check ServiceAccount permissions}
    C -->|has secrets access| D[List all secrets in namespace]
    D --> E[Extract database credentials]
    E --> F[Connect to production database]
    F --> G[Exfiltrate customer data]

    C -->|has cloud role| H[Get temporary AWS credentials]
    H --> I[Access S3 buckets]
    I --> J[Download sensitive files]

    style A fill:#ff0000,color:#fff
    style G fill:#ff0000,color:#fff
    style J fill:#ff0000,color:#fff
```

### Scenario 2: Privilege Escalation

```mermaid
flowchart TD
    A[Attacker in low-privilege pod] --> B{Can create pods?}
    B -->|yes| C[Create pod with privileged SA]
    C --> D[New pod has cluster-admin]
    D --> E[Full cluster compromise]

    B -->|no| F{Can modify deployments?}
    F -->|yes| G[Inject container into existing deployment]
    G --> H[Inherit target's ServiceAccount]
    H --> I[Access target's permissions]

    style A fill:#ffaa00
    style E fill:#ff0000,color:#fff
    style I fill:#ff0000,color:#fff
```

## OpenShift Security Context Constraints

For OpenShift clusters, Identity Chain also analyzes Security Context Constraints (SCCs) - OpenShift's mechanism for controlling what pods can do at the container runtime level.

SCCs control:
- Privileged containers
- Host namespace access (network, PID, IPC)
- Volume types (hostPath, etc.)
- User/group IDs
- Linux capabilities

```mermaid
graph TB
    subgraph "OpenShift SCC Analysis"
        SCC1[privileged SCC] -->|allows| P1[hostNetwork]
        SCC1 -->|allows| P2[privileged containers]
        SCC1 -->|allows| P3[hostPID]

        SCC2[restricted SCC] -->|enforces| R1[runAsNonRoot]
        SCC2 -->|enforces| R2[drop ALL capabilities]

        SA1[ServiceAccount] -->|can use| SCC1
        SA2[ServiceAccount] -->|can use| SCC2
    end

    style SCC1 fill:#ff6b6b
    style P1 fill:#ff6b6b
    style P2 fill:#ff6b6b
    style P3 fill:#ff6b6b
```

Identity Chain scores each SCC by risk and identifies which service accounts can use privileged SCCs - critical for understanding container escape risk.

## How Identity Chain Helps

Identity Chain (`idc`) automatically maps these relationships and generates an interactive security dashboard:

```mermaid
graph TB
    subgraph "Data Collection"
        K8S[Kubernetes API]
        AWS[AWS IAM API]
        GCP[GCP IAM API]
    end

    subgraph "Analysis"
        GRAPH[Build Identity Graph]
        BLAST[Blast Radius]
        ATTACK[Attack Paths]
        RBAC[RBAC Audit]
        PERMS[Permissions Audit]
    end

    subgraph "Output"
        DASH[Interactive Dashboard]
        JSON[JSON for Automation]
    end

    K8S --> GRAPH
    AWS --> GRAPH
    GCP --> GRAPH

    GRAPH --> BLAST
    GRAPH --> ATTACK
    GRAPH --> RBAC
    GRAPH --> PERMS

    BLAST --> DASH
    ATTACK --> DASH
    RBAC --> DASH
    PERMS --> DASH
    BLAST --> JSON
```

### Example Output

When you run `idc blast --all -A --include-cloud`, you get:

```
Workload: api-server (Deployment)
├── ServiceAccount: api-sa
│   ├── K8s Access:
│   │   ├── [CRITICAL] Can READ ALL SECRETS in api namespace
│   │   ├── [HIGH] Can CREATE/MODIFY PODS - potential container injection
│   │   └── [MEDIUM] Read access to configmaps
│   │
│   └── Cloud Access (AWS IRSA):
│       ├── Role: arn:aws:iam::123456789:role/api-role
│       ├── [HIGH] Read/Write S3 access to ALL buckets
│       └── [CRITICAL] Full Secrets Manager access
│
└── Blast Radius: CRITICAL
    If compromised, attacker can:
    - Read all secrets in namespace (credential exposure)
    - Access all S3 buckets in AWS account
    - Read/write all Secrets Manager secrets
```

## The Graph Model

Identity Chain builds an in-memory graph representing all identity relationships:

```mermaid
graph TB
    subgraph "Node Types"
        NT1[Workload<br/>Pod, Deployment, etc.]
        NT2[ServiceAccount]
        NT3[Role / ClusterRole]
        NT4[K8s Resource<br/>secrets, pods, etc.]
        NT5[Cloud Role<br/>AWS, GCP, Azure]
        NT6[Cloud Resource<br/>S3, Secrets Manager]
    end

    subgraph "Edge Types"
        NT1 -->|uses| NT2
        NT2 -->|binds| NT3
        NT3 -->|grants| NT4
        NT2 -->|assumes| NT5
        NT5 -->|allows| NT6
    end
```

## Risk Classification

Identity Chain classifies risks based on what can be accessed:

```mermaid
graph TD
    subgraph "CRITICAL Risk"
        C1[Secrets access]
        C2[RBAC modification]
        C3[Cloud admin policies]
        C4[Cluster-admin role]
    end

    subgraph "HIGH Risk"
        H1[Pod exec access]
        H2[Pod creation]
        H3[Cloud secrets access]
        H4[Database access]
    end

    subgraph "MEDIUM Risk"
        M1[ConfigMap access]
        M2[Deployment modification]
        M3[S3 read-only]
    end

    subgraph "LOW Risk"
        L1[Pod list/watch]
        L2[Service discovery]
    end

    style C1 fill:#ff0000,color:#fff
    style C2 fill:#ff0000,color:#fff
    style C3 fill:#ff0000,color:#fff
    style C4 fill:#ff0000,color:#fff

    style H1 fill:#ff6b6b
    style H2 fill:#ff6b6b
    style H3 fill:#ff6b6b
    style H4 fill:#ff6b6b

    style M1 fill:#ffa500
    style M2 fill:#ffa500
    style M3 fill:#ffa500
```

## Use Cases

### Security Assessment

Before deploying to production, understand the blast radius of each workload:

```bash
# Generate comprehensive report
idc blast --all -A --include-cloud --aws-region us-west-2 -o html > security-report.html

# Find critical risks
idc blast --all -A -o json | jq '.[] | select(.max_severity == "critical")'
```

### Incident Response

When a pod is compromised, immediately understand the impact:

```bash
# What can the attacker access from this pod?
idc blast --workload pod/compromised-pod -n production --include-cloud
```

### Compliance & Audit

Demonstrate least-privilege adherence:

```bash
# Find service accounts with secrets access
idc blast --all -A -o json | jq '.[] | select(.k8s_resources[]?.name == "secrets")'

# Find overprivileged cloud access
idc blast --all -A --include-cloud -o json | jq '.[] | select(.cloud_roles[]?.policies[]?.is_admin == true)'
```

## Architecture Deep Dive

```mermaid
flowchart TB
    subgraph "Data Collection"
        KC[Kubernetes Collector]
        AC[AWS IRSA Collector]
        GC[GCP Workload Identity Collector]
        AZC[Azure Pod Identity Collector]
    end

    subgraph "Graph Builder"
        GB[Graph Builder]
        NM[Node Manager]
        EM[Edge Manager]
    end

    subgraph "Analysis Engine"
        BR[Blast Radius Calculator]
        PE[Privilege Escalation Detector]
        UP[Unused Permission Finder]
    end

    subgraph "Output Renderers"
        TR[Table Renderer]
        JR[JSON Renderer]
        HR[HTML Renderer]
        DR[DOT/Graphviz Renderer]
    end

    KC --> GB
    AC --> GB
    GC --> GB
    AZC --> GB

    GB --> NM
    GB --> EM

    NM --> BR
    EM --> BR
    NM --> PE
    EM --> PE

    BR --> TR
    BR --> JR
    BR --> HR
    BR --> DR
```

## Getting Started

```bash
# Install via Homebrew
brew install nelssec/tap/idc

# Generate interactive dashboard
idc dashboard -A --include-cloud --aws-region us-west-2 -f dashboard.html
open dashboard.html

# Or run individual commands
idc blast --all -A                    # Blast radius analysis
idc whocan get secrets -A             # Who can access secrets?
idc attack-path --all -A              # Attack path visualization
idc scc -A                            # OpenShift SCC analysis
idc sa-lifecycle -A                   # Find orphaned service accounts
```

## Auto-Remediation

Identity Chain can generate fix manifests for security findings:

```bash
# Generate fixes for all findings
idc remediate -A -f fixes.yaml

# Apply the fixes
kubectl apply -f fixes.yaml
```

This generates ready-to-apply Kubernetes YAML for:
- **RBAC issues**: Replace cluster-admin bindings, remove secrets access, replace wildcards
- **Pod security**: Disable privileged, add security contexts, drop capabilities
- **Network policies**: Create default-deny policies with DNS egress

## Custom Security Checks

Define organization-specific security rules in YAML:

```yaml
checks:
  - id: ORG001
    name: "Production namespace requires resource limits"
    severity: high
    match:
      kind: Workload
      namespacePattern: "^prod-"
    condition:
      missingSecurityField: "resourceLimits"
```

Run custom checks:
```bash
idc check -A --config org-checks.yaml
```

## Multi-Cluster Security Posture

Track security across multiple clusters over time:

```bash
# Configure clusters
idc clusters add --name prod --context prod-eks
idc clusters add --name staging --context staging-eks

# Scan all clusters
idc clusters scan

# Compare security posture
idc trend

# View historical data
idc history --cluster prod
```

```mermaid
graph LR
    subgraph "Multi-Cluster View"
        C1[Prod Cluster] --> S[Central Store]
        C2[Staging Cluster] --> S
        C3[Dev Cluster] --> S
    end

    S --> T[Trend Analysis]
    S --> H[Historical Data]
    S --> R[Comparison Reports]
```

## Conclusion

Understanding the blast radius of Kubernetes workloads is critical for:
- **Prevention**: Identify overprivileged workloads before they're exploited
- **Detection**: Know what to monitor for each identity
- **Response**: Quickly scope the impact of a breach
- **Compliance**: Demonstrate least-privilege implementation

Identity Chain automates this analysis, giving security teams visibility into the complete identity chain from workload to cloud resource.

---

*Identity Chain is open source. Contributions welcome at [github.com/nelssec/identity-chain](https://github.com/nelssec/identity-chain)*
