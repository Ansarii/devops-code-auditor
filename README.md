# DevOps & Cloud Code Auditor (MCP Server)

[![Model Context Protocol](https://img.shields.io/badge/MCP-Server-blue.svg)](https://modelcontextprotocol.io)
[![Glama Quality Score](https://glama.ai/mcp/servers/Ansarii/devops-code-auditor/badges/score.svg)](https://glama.ai/mcp/servers/Ansarii/devops-code-auditor)
[![Python 3.12](https://img.shields.io/badge/Python-3.12-brightgreen.svg)](https://python.org)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Transport: stdio](https://img.shields.io/badge/Transport-stdio-orange.svg)](https://modelcontextprotocol.io/docs/concepts/transports)

A production-ready **Model Context Protocol (MCP) Server** providing AI coding assistants (Claude Desktop, Cursor, Windsurf, Cline) with automated static analysis tools to prevent production outages, cloud cost leaks, and security vulnerabilities.

---

## 🌟 Capabilities & Audited Rule Sets

This server inspects codebases across three mission-critical engineering vectors:

1. **Cloud Cost Leaks (Terraform / HCL / AWS):**
   * **`EBS_GP2`**: Identifies legacy `gp2` EBS volumes (`gp3` provides equal durability with ~20% baseline cost reduction and higher baseline IOPS).
   * **`PUBLIC_IP`**: Flags unneeded `associate_public_ip_address = true` incurring hourly AWS IPv4 charges ($0.005/hr/IP).
   * **`CW_NO_RETENTION`**: Catches `aws_cloudwatch_log_group` missing retention policies (preventing infinite unbudgeted log ingestion costs).
   * **`S3_NO_LIFECYCLE`**: Detects S3 buckets lacking Glacier lifecycle transitions.
   * **`RDS_MULTIAZ_NONPROD` & `RDS_PROVISIONED_IOPS_NONPROD`**: Flags doubled database infrastructure costs on development and staging environments.

2. **PostgreSQL Migration Table Lock Hazards:**
   * **`INDEX_NOT_CONCURRENT`**: Detects `CREATE INDEX` missing `CONCURRENTLY` (which acquires an `EXCLUSIVE` lock and halts table writes in production).
   * **`NOT_NULL_VOLATILE_DEFAULT`**: Catches `ADD COLUMN ... NOT NULL DEFAULT <func()>` rewriting every table row under an `ACCESS EXCLUSIVE` lock.
   * **`FK_NO_INDEX`**: Flags unindexed foreign key constraints causing cascading table-level sequential lock scans on parent updates/deletes.
   * **`FOR_UPDATE_UNBOUNDED`**: Catches `SELECT ... FOR UPDATE` missing `LIMIT` or `SKIP LOCKED`, preventing deadlocks.

3. **OWASP & Full-Stack Next.js API Security:**
   * **`NEXT_PUBLIC_SECRET_LEAK`**: Flags sensitive tokens and private API keys prefixed with `NEXT_PUBLIC_` that leak into public client browser bundles.
   * **`NEXTJS_SERVER_ACTION_NO_AUTH`**: Flags Next.js 14/15 Server Actions exporting mutations without explicit session auth verification.
   * **`SQLI_RAW_INTERPOLATION`**: Identifies raw SQL query templates using string interpolation instead of parameterized inputs.
   * **`SSRF_UNVALIDATED_FETCH`**: Catches external fetch calls consuming user inputs without protocol/hostname validation.

---

## 🛠️ MCP Tools Exposed

This server implements the official Model Context Protocol specification (`tools/list` and `tools/call`):

### 1. `audit_devops_repository`
Clones a public Git repository shallowly without executing hooks, performs AST and regex static syntax audits, and returns structured findings and a formatted Markdown report.

* **Parameters:**
  * `repository_url` (string, required): Public Git URL of the repository to audit (e.g. `https://github.com/example/cloud-infra`).
  * `sub_directory` (string, optional): Specific subdirectory within the repository to inspect (e.g. `terraform/` or `prisma/migrations/`).
* **Returns:**
  * `status`: "success" | "error"
  * `total_findings`: Number of detected issues
  * `findings`: Array of detailed vulnerability records (file, line number, rule ID, severity, message, fix code)
  * `markdown_report`: Human-readable summary table

### 2. `audit_devops_code`
Directly audits a raw code snippet of Terraform (HCL), PostgreSQL migration (SQL), or Next.js API/Server Action code.

* **Parameters:**
  * `code` (string, required): The source code string to audit.
  * `file_type` (string, optional, default: "auto"): One of `"terraform"`, `"postgres"`, `"nextjs"`, or `"auto"`.
* **Returns:** Structured JSON findings with exact drop-in code fixes.

### 3. `audit_local_devops_directory`
Audits a local filesystem directory on the host machine before submitting a Pull Request or deploying to staging.

* **Parameters:**
  * `directory_path` (string, required): Absolute filesystem path to the target folder.
* **Returns:** Structured JSON findings and severity breakdown.

---

## 🚀 Client Configuration & Quickstart

### 1. Claude Desktop Setup
Add the server to your `claude_desktop_config.json`:

```json
{
  "mcpServers": {
    "devops-code-auditor": {
      "command": "python3",
      "args": ["/path/to/devops-code-auditor/server.py"]
    }
  }
}
```

### 2. Cursor IDE / Windsurf Setup
In Cursor, navigate to **Settings → Features → MCP → Add New MCP Server**:
* **Name:** `devops-code-auditor`
* **Type:** `command`
* **Command:** `python3 /absolute/path/to/devops-code-auditor/server.py`

### 3. Docker Execution
Run the isolated container via Docker:

```json
{
  "mcpServers": {
    "devops-code-auditor": {
      "command": "docker",
      "args": [
        "run",
        "-i",
        "--rm",
        "ghcr.io/ansarii/devops-code-auditor"
      ]
    }
  }
}
```

---

## 💻 Example Agent Usage

Once connected, your AI assistant can evaluate migration files and cloud manifests on demand:

```text
User: "Check this PostgreSQL migration before I run it on production:
CREATE INDEX idx_orders_user_id ON orders (user_id);"

Claude (Tool Call):
audit_devops_code({
  "code": "CREATE INDEX idx_orders_user_id ON orders (user_id);",
  "file_type": "postgres"
})

Result:
{
  "status": "success",
  "total_findings": 1,
  "findings": [
    {
      "suite": "postgres-locks",
      "rule": "INDEX_NOT_CONCURRENT",
      "severity": "high",
      "file": "migration.sql",
      "line": 1,
      "message": "CREATE INDEX on \"orders\" without CONCURRENTLY blocks table writes during build.",
      "fix": "CREATE INDEX CONCURRENTLY idx_orders_user_id ON orders (user_id);"
    }
  ]
}
```

---

## 🔒 Security Guarantee: Zero Execution

This server executes **100% static analysis** using AST pattern matching and regex verification. It never executes untrusted shell commands, arbitrary Python code, or database connections on your machine.

---

## 📜 License

MIT License — Copyright (c) 2026 Neon Innovation Lab.
Maintained by [Neon Innovation Lab](https://neoninnovationlab.com).
