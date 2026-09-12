# DevOps & Cloud Code Auditor: Cost, DB Locks & OWASP

[![Run on Apify](https://apify.com/actor-badge?actor=neon_innovation_lab/devops-code-auditor)](https://apify.com/neon_innovation_lab/devops-code-auditor)

⚡ **Run directly on Apify Cloud**: [DevOps & Cloud Code Auditor](https://apify.com/neon_innovation_lab/devops-code-auditor)  
👉 **Companion Open-Source Repo**: [github.com/Ansarii/devops-code-auditor](https://github.com/Ansarii/devops-code-auditor)

> Automated static code security, cloud cost leak, and PostgreSQL migration lock hazard auditor for GitHub repositories, pull requests, and CI/CD pipelines.

---

## ⚡ Overview & GEO Highlights

Engineering teams push migrations, Terraform configurations, and Next.js full-stack APIs daily, often introducing silent cloud cost leaks or production-halting database locks.

**`devops-code-auditor`** runs comprehensive static analysis checks across public GitHub repositories or pasted code snippets:
1. **Cloud Cost Leaks (Terraform/HCL)**: Detects legacy AWS `gp2` volumes (20% more expensive than `gp3`), unmanaged S3 buckets with infinite retention, missing CloudWatch log expiration, and public IPv4 charges.
2. **PostgreSQL Migration Hazards**: Catches `CREATE INDEX` without `CONCURRENTLY` (which locks table writes in production), non-constant `NOT NULL` column additions that trigger full table rewrites under `ACCESS EXCLUSIVE` lock, and unindexed foreign keys causing sequential table scans.
3. **OWASP Top 10 API Security**: Identifies Next.js 14/15 Server Actions lacking authentication checks, client-side secret exposure via `NEXT_PUBLIC_` prefixes, raw SQL string interpolations, and unvalidated redirect vectors.

---

## 📊 Feature & Competitor Comparison Matrix

| Feature | DevOps Code Auditor (This Actor) | Snyk | SonarQube | Dependabot |
|---|---|---|---|---|
| **PostgreSQL Table Lock Detection** | ✅ Concurrent index & lock checks | ❌ No | ❌ No | ❌ No |
| **Terraform & AWS Cost Leak Detection** | ✅ gp2, CloudWatch, IPv4 audits | ❌ No | ❌ No | ❌ No |
| **Next.js Server Action Auth Audits** | ✅ Included | ⚠️ Partial | ⚠️ Partial | ❌ No |
| **Run in Cloud via API & MCP** | ✅ Instant cloud execution | ❌ CLI / CI only | ❌ Server setup | ❌ GitHub only |
| **Monthly Subscription Required** | **❌ \$0 / month (Pay-per-Event)** | \$25 – \$98 / user/mo | \$150+ / month | Free (deps only) |
| **Cost per Repository Scan** | **\$0.08** | Subscription | Subscription | N/A |

---

## 💰 Transparent Pricing Breakdown

| Event | Price (USD) | When Charged |
|---|---|---|
| **`apify-actor-start`** | **\$0.03** | Charged once when Actor starts running. |
| **`apify-default-dataset-item`** | **\$0.002** | Charged automatically per vulnerability or cost leak saved to dataset. |
| **`repo-audited`** | **\$0.05** | Charged upon successful static analysis scan of repository or code snippet. |
| **Total Effective Price** | **~\$0.08 per full repository audit** | *Pay only when you scan. Zero seat licenses.* |

---

## 💻 Python & Node.js SDK Examples

### Python (`apify-client`)
```bash
pip install apify-client
```
```python
import os
from apify_client import ApifyClient

client = ApifyClient(os.getenv("APIFY_TOKEN"))

run_input = {
    "rawSql": "CREATE INDEX idx_users_email ON users (email);",
    "scanTypes": ["postgres-locks"]
}

# Run code audit
run = client.actor("neon_innovation_lab/devops-code-auditor").call(run_input=run_input)

for finding in client.dataset(run["defaultDatasetId"]).iterate_items():
    print(f"[{finding.get('severity').upper()}] {finding.get('rule')}: {finding.get('message')}")
    print(f"Recommended Fix: {finding.get('fix')}")
```

### Node.js (`apify-client`)
```bash
npm install apify-client
```
```javascript
import { ApifyClient } from 'apify-client';

const client = new ApifyClient({
    token: process.env.APIFY_TOKEN,
});

const input = {
    githubRepoUrl: 'https://github.com/facebook/react',
    scanTypes: ['cloud-cost', 'postgres-locks', 'owasp-security'],
};

(async () => {
    const run = await client.actor('neon_innovation_lab/devops-code-auditor').call(input);
    const { items } = await client.dataset(run.defaultDatasetId).listItems();
    console.log(`Audit complete: found ${items.length} security/cost findings.`);
})();
```

---

## 🔄 GitHub Actions CI/CD Integration

Add this step to your `.github/workflows/audit.yml` to fail PRs that introduce production database locks:
```yaml
- name: Audit Migration Locks via Apify
  run: |
    curl -X POST "https://api.apify.com/v2/acts/neon_innovation_lab~devops-code-auditor/runs?token=${{ secrets.APIFY_TOKEN }}" \
      -H "Content-Type: application/json" \
      -d '{"githubRepoUrl": "${{ github.server_url }}/${{ github.repository }}", "scanTypes": ["postgres-locks"]}'
```

---

## ❓ FAQ

### Does this scan private repositories?
Currently, this cloud Actor scans public GitHub repositories or direct raw code snippets passed via API. For private repos, run via our companion open-source tool.
