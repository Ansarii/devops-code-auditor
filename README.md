# DevOps & Cloud Code Auditor

[![Run on Apify](https://apify.com/actor-badge?actor=neon_innovation_lab/devops-code-auditor)](https://apify.com/neon_innovation_lab/devops-code-auditor)

⚡ **Run directly on Apify Cloud**: [DevOps & Cloud Code Auditor](https://apify.com/neon_innovation_lab/devops-code-auditor)

> **Automated static code security, cloud cost, and PostgreSQL lock hazard auditor for GitHub repositories and CI/CD pipelines.**

DevOps & Cloud Code Auditor scans public GitHub repositories and code snippets to detect:
1. **Cloud Cost Leaks (Terraform/HCL):** Legacy gp2 volumes, infinite CloudWatch log accumulation, public IPv4 waste, and unmanaged S3 buckets.
2. **PostgreSQL Migration Locks:** Dangerous `CREATE INDEX` statements without `CONCURRENTLY`, non-constant `NOT NULL` defaults that rewrite tables under `ACCESS EXCLUSIVE` lock, and unindexed foreign keys.
3. **OWASP Top 10 API Vulnerabilities:** Next.js 14/15 App Router Server Actions missing authorization, client-side secret exposure via `NEXT_PUBLIC_`, raw SQL string template interpolations, and unvalidated redirects.

---

## ⚡ How to Use

### 1. Scan a Public GitHub Repository
Simply pass any public GitHub URL in the input:
```json
{
  "githubRepoUrl": "https://github.com/neoninnovationlab/neon-innovation-lab-ai-devops-skills",
  "scanTypes": ["cloud-cost", "postgres-locks", "owasp-security"]
}
```

### 2. Quick Snippet Scan
You can also paste raw code snippets directly without providing a repository:
```json
{
  "rawSql": "CREATE INDEX idx_users_email ON users (email);",
  "scanTypes": ["postgres-locks"]
}
```

---

## 📊 Dataset Output

Every run outputs structured findings into the default dataset:
```json
{
  "suite": "postgres-locks",
  "rule": "INDEX_NOT_CONCURRENT",
  "severity": "high",
  "file": "migrations/001_add_indexes.sql",
  "line": 4,
  "snippet": "CREATE INDEX idx_users_email ON users (email);",
  "message": "CREATE INDEX on \"users\" without CONCURRENTLY blocks table writes during build.",
  "fix": "CREATE INDEX CONCURRENTLY idx_users_email ON users (email);"
}
```

---

## 🔗 Companion Open-Source AI Agent Skills

Prefer running these checks natively inside **Claude Code**, **Cursor IDE**, or **GitHub Copilot**?  
Check out our companion open-source repository:  
👉 **[neon-innovation-lab-ai-devops-skills](https://github.com/neoninnovationlab/neon-innovation-lab-ai-devops-skills)**
