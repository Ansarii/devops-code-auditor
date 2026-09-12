import asyncio
import os
import re
import shutil
import subprocess
import tempfile
from pathlib import Path
from apify import Actor


# --- Scanner 1: Terraform Cost Rules ---

def scan_terraform_text(file_path: str, text: str):
    findings = []
    lines = text.splitlines()

    for i, line in enumerate(lines, 1):
        if re.search(r'type\s*=\s*"gp2"', line):
            findings.append({
                "suite": "cloud-cost",
                "rule": "EBS_GP2",
                "severity": "medium",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": "gp2 volume declared — gp3 offers same durability with ~20% lower baseline cost and better IOPS.",
                "fix": line.replace("gp2", "gp3").strip()
            })

        if re.search(r'associate_public_ip_address\s*=\s*true', line):
            findings.append({
                "suite": "cloud-cost",
                "rule": "PUBLIC_IP",
                "severity": "medium",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": "Public IPv4 addresses incur an hourly charge ($0.005/hr) — confirm public access is required.",
                "fix": "associate_public_ip_address = false"
            })

    for m in re.finditer(r'resource\s+"aws_cloudwatch_log_group"\s+"([^"]+)"\s*{([^}]*)}', text, re.S):
        block = m.group(2)
        if "retention_in_days" not in block:
            line_no = text[:m.start()].count("\n") + 1
            findings.append({
                "suite": "cloud-cost",
                "rule": "CW_NO_RETENTION",
                "severity": "high",
                "file": file_path,
                "line": line_no,
                "snippet": m.group(0)[:80] + "...",
                "message": f'aws_cloudwatch_log_group "{m.group(1)}" has no retention policy (defaults to Never Expire).',
                "fix": "retention_in_days = 90  # inside resource block"
            })

    bucket_names = set(re.findall(r'resource\s+"aws_s3_bucket"\s+"([^"]+)"', text))
    lifecycle_targets = set(re.findall(r'resource\s+"aws_s3_bucket_lifecycle_configuration"\s+"[^"]+"\s*{[^}]*bucket\s*=\s*aws_s3_bucket\.([^.\s]+)', text, re.S))
    for name in bucket_names:
        if name not in lifecycle_targets:
            findings.append({
                "suite": "cloud-cost",
                "rule": "S3_NO_LIFECYCLE",
                "severity": "medium",
                "file": file_path,
                "line": 1,
                "snippet": f'resource "aws_s3_bucket" "{name}"',
                "message": f'S3 bucket "{name}" has no matching lifecycle configuration for cold data transitions.',
                "fix": "Add aws_s3_bucket_lifecycle_configuration with Glacier transition rules."
            })

    for m in re.finditer(r'resource\s+"aws_db_instance"\s+"([^"]+)"\s*{([^}]*)}', text, re.S):
        name, block = m.group(1), m.group(2)
        if re.search(r'(dev|staging|test|sandbox)', name + block, re.I):
            line_no = text[:m.start()].count("\n") + 1
            if re.search(r'multi_az\s*=\s*true', block):
                findings.append({
                    "suite": "cloud-cost",
                    "rule": "RDS_MULTIAZ_NONPROD",
                    "severity": "medium",
                    "file": file_path,
                    "line": line_no,
                    "snippet": f'aws_db_instance "{name}"',
                    "message": "multi_az = true declared on what appears to be a non-production database (doubles cost).",
                    "fix": "multi_az = false"
                })
            if re.search(r'storage_type\s*=\s*"io[12]"', block):
                findings.append({
                    "suite": "cloud-cost",
                    "rule": "RDS_PROVISIONED_IOPS_NONPROD",
                    "severity": "medium",
                    "file": file_path,
                    "line": line_no,
                    "snippet": f'aws_db_instance "{name}"',
                    "message": "Provisioned IOPS (io1/io2) on non-prod database — gp3 is usually sufficient.",
                    "fix": 'storage_type = "gp3"'
                })

    return findings


# --- Scanner 2: PostgreSQL Migration Lock Rules ---

NOT_NULL_DEFAULT_RE = re.compile(r'ALTER\s+TABLE\s+(\w+)\s+ADD\s+COLUMN\s+(\w+)\s+\S+.*?NOT\s+NULL\s+DEFAULT\s+(\S+)', re.I)
CREATE_INDEX_RE = re.compile(r'CREATE\s+(UNIQUE\s+)?INDEX\s+(?!CONCURRENTLY)(\w+)?\s*ON\s+(\w+)', re.I)
FK_RE = re.compile(r'ALTER\s+TABLE\s+(\w+)\s+ADD\s+CONSTRAINT\s+\w+\s+FOREIGN\s+KEY\s*\(([^)]+)\)\s*REFERENCES\s+(\w+)', re.I)
CREATE_INDEX_ANY_RE = re.compile(r'CREATE\s+(?:UNIQUE\s+)?INDEX\s+(?:CONCURRENTLY\s+)?\w+\s+ON\s+(\w+)\s*\(([^)]+)\)', re.I)
DROP_RE = re.compile(r'DROP\s+(TABLE|COLUMN)\s+(\w+)', re.I)
FOR_UPDATE_RE = re.compile(r'FOR\s+UPDATE', re.I)


def scan_postgres_text(file_path: str, text: str):
    findings = []
    lines = text.splitlines()

    for i, line in enumerate(lines, 1):
        m = NOT_NULL_DEFAULT_RE.search(line)
        if m:
            table, col, default = m.groups()
            if not re.match(r'^[\'"]?[\w.]+[\'"]?$', default) or "()" in default:
                findings.append({
                    "suite": "postgres-locks",
                    "rule": "NOT_NULL_VOLATILE_DEFAULT",
                    "severity": "high",
                    "file": file_path,
                    "line": i,
                    "snippet": line.strip(),
                    "message": f'ADD COLUMN "{col}" NOT NULL DEFAULT {default} rewrites every row under an ACCESS EXCLUSIVE lock.',
                    "fix": f"ALTER TABLE {table} ADD COLUMN {col} <type>; -- nullable first\n-- then add CHECK ({col} IS NOT NULL) NOT VALID and VALIDATE CONSTRAINT"
                })

        m = CREATE_INDEX_RE.search(line)
        if m and "CONCURRENTLY" not in line.upper():
            _, _, table = m.groups()
            findings.append({
                "suite": "postgres-locks",
                "rule": "INDEX_NOT_CONCURRENT",
                "severity": "high",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": f'CREATE INDEX on "{table}" without CONCURRENTLY blocks table writes during build.',
                "fix": re.sub(r'CREATE\s+(UNIQUE\s+)?INDEX', lambda mm: mm.group(0).replace("INDEX", "INDEX CONCURRENTLY"), line, flags=re.I).strip()
            })

        m = DROP_RE.search(line)
        if m:
            kind, name = m.groups()
            findings.append({
                "suite": "postgres-locks",
                "rule": f"DROP_{kind.upper()}_LIVE",
                "severity": "medium",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": f'DROP {kind} "{name}" may break live application code — verify soft deprecation first.',
                "fix": "-- Expand-contract: stop application reads/writes in previous deploy before dropping."
            })

        if FOR_UPDATE_RE.search(line) and not re.search(r'LIMIT\s+\d+', line, re.I):
            findings.append({
                "suite": "postgres-locks",
                "rule": "FOR_UPDATE_UNBOUNDED",
                "severity": "medium",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": "SELECT ... FOR UPDATE without LIMIT risks unbounded row locking and deadlocks under concurrent traffic.",
                "fix": line.strip() + " LIMIT 50 SKIP LOCKED;"
            })

    indexed_cols = set()
    for m in CREATE_INDEX_ANY_RE.finditer(text):
        table, cols = m.groups()
        for c in cols.split(","):
            indexed_cols.add((table.strip(), c.strip()))

    for m in FK_RE.finditer(text):
        table, cols, ref_table = m.groups()
        line_no = text[:m.start()].count("\n") + 1
        for c in cols.split(","):
            c = c.strip()
            if (table, c) not in indexed_cols:
                findings.append({
                    "suite": "postgres-locks",
                    "rule": "FK_NO_INDEX",
                    "severity": "high",
                    "file": file_path,
                    "line": line_no,
                    "snippet": m.group(0).strip(),
                    "message": f'Foreign key {table}.{c} -> {ref_table} has no matching index, causing full-table scans on parent updates/deletes.',
                    "fix": f"CREATE INDEX CONCURRENTLY idx_{table}_{c} ON {table} ({c});"
                })

    return findings


# --- Scanner 3: OWASP & API Security Rules ---

NEXT_PUBLIC_SECRET_RE = re.compile(r'NEXT_PUBLIC_(?:SECRET|PRIVATE|KEY|TOKEN|PASSWORD|API_KEY|AUTH|CREDENTIAL|DATABASE|DB_URL)', re.I)
UNVALIDATED_REDIRECT_RE = re.compile(r'(?:redirect|router\.push)\s*\(\s*(?:req\.|searchParams\.get|params\.|url\.searchParams)', re.I)
RAW_SQL_TEMPLATE_RE = re.compile(r'(?:\$queryRawUnsafe|db\.query|connection\.query|client\.query|sequelize\.query)\s*\(\s*`[^`]*\$\{', re.I)
SSRF_FETCH_RE = re.compile(r'(?:fetch|axios\.(?:get|post)|requests\.(?:get|post)|http\.get)\s*\(\s*(?:req\.body|body\.|params\.|request\.(?:data|json))', re.I)


def scan_security_text(file_path: str, text: str):
    findings = []
    lines = text.splitlines()

    for i, line in enumerate(lines, 1):
        m = NEXT_PUBLIC_SECRET_RE.search(line)
        if m:
            findings.append({
                "suite": "owasp-security",
                "rule": "NEXT_PUBLIC_SECRET_LEAK",
                "severity": "critical",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": f"Credential '{m.group(0)}' uses NEXT_PUBLIC_ prefix, bundling secrets into client JS bundles.",
                "fix": line.replace("NEXT_PUBLIC_", "").strip()
            })

        m_redir = UNVALIDATED_REDIRECT_RE.search(line)
        if m_redir:
            findings.append({
                "suite": "owasp-security",
                "rule": "UNVALIDATED_REDIRECT",
                "severity": "medium",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": "Redirect consumes request parameters without domain allowlist validation (open redirect).",
                "fix": "const safeUrl = ALLOWED_HOSTS.includes(target) ? target : '/dashboard';"
            })

        m_sql = RAW_SQL_TEMPLATE_RE.search(line)
        if m_sql:
            findings.append({
                "suite": "owasp-security",
                "rule": "SQLI_RAW_INTERPOLATION",
                "severity": "critical",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": "Raw SQL query uses template string interpolation (${...}) instead of parameterized inputs.",
                "fix": "Use parameterized inputs: db.query('SELECT * FROM table WHERE id = $1', [id])"
            })

        m_ssrf = SSRF_FETCH_RE.search(line)
        if m_ssrf:
            findings.append({
                "suite": "owasp-security",
                "rule": "SSRF_UNVALIDATED_FETCH",
                "severity": "high",
                "file": file_path,
                "line": i,
                "snippet": line.strip(),
                "message": "HTTP client fetches user-supplied URL directly without hostname allowlist or private IP blocking.",
                "fix": "Validate URL protocol/hostname and block internal ranges (127.0.0.1, 169.254.169.254)."
            })

    if '"use server"' in text or "'use server'" in text:
        server_actions = re.finditer(r'export\s+async\s+function\s+([a-zA-Z0-9_]+)\s*\(([^)]*)\)\s*\{([^}]*)\}', text)
        for sa in server_actions:
            name, params, body = sa.group(1), sa.group(2), sa.group(3)
            has_auth = re.search(r'(auth\s*\(\)|session|getSession|getCurrentUser|verifyToken|currentUser)', body)
            if not has_auth:
                line_no = text[:sa.start()].count("\n") + 1
                findings.append({
                    "suite": "owasp-security",
                    "rule": "NEXTJS_SERVER_ACTION_NO_AUTH",
                    "severity": "high",
                    "file": file_path,
                    "line": line_no,
                    "snippet": f'export async function {name}({params})',
                    "message": f"Server Action '{name}' lacks explicit session authentication verification.",
                    "fix": "const session = await auth();\nif (!session?.user) throw new Error('Unauthorized');"
                })

    return findings


# --- Main Apify Actor Execution ---

async def main():
    async with Actor:
        actor_input = await Actor.get_input() or {}

        # 1. Charge standard Actor start fee (PPE pricing rule)
        try:
            await Actor.charge(event_name="apify-actor-start", count=1)
        except Exception:
            pass  # Fallback gracefully in testing environments

        github_url = actor_input.get("githubRepoUrl")
        raw_tf = actor_input.get("rawTerraform")
        raw_sql = actor_input.get("rawSql")
        raw_code = actor_input.get("rawCode")
        scan_types = actor_input.get("scanTypes", ["cloud-cost", "postgres-locks", "owasp-security"])

        all_findings = []
        temp_dir = None

        try:
            # Mode A: Git Repository Scan
            if github_url:
                Actor.log.info(f"Cloning public repository: {github_url}")
                temp_dir = tempfile.mkdtemp(prefix="apify_audit_")
                try:
                    subprocess.run(["git", "clone", "--depth", "1", github_url, temp_dir], check=True, capture_output=True, timeout=60)
                except Exception as e:
                    Actor.log.error(f"Failed to clone repository {github_url}: {e}")
                    all_findings.append({
                        "suite": "system",
                        "rule": "GIT_CLONE_FAILED",
                        "severity": "critical",
                        "file": github_url,
                        "line": 0,
                        "snippet": str(e),
                        "message": f"Could not clone repository: {e}",
                        "fix": "Verify the repository is public and the URL is accessible."
                    })

                if not all_findings:
                    root = Path(temp_dir)
                    for file_path in root.rglob("*"):
                        if not file_path.is_file():
                            continue
                        if any(p in file_path.parts for p in [".git", "node_modules", "dist", ".next", "__pycache__"]):
                            continue

                        rel_path = str(file_path.relative_to(root))
                        content = file_path.read_text(errors="ignore")

                        if "cloud-cost" in scan_types and file_path.suffix.lower() == ".tf":
                            all_findings.extend(scan_terraform_text(rel_path, content))

                        if "postgres-locks" in scan_types and file_path.suffix.lower() == ".sql":
                            all_findings.extend(scan_postgres_text(rel_path, content))

                        if "owasp-security" in scan_types and file_path.suffix.lower() in [".ts", ".tsx", ".js", ".jsx", ".py"]:
                            all_findings.extend(scan_security_text(rel_path, content))

            # Mode B: Raw Snippet Scans
            if raw_tf and "cloud-cost" in scan_types:
                all_findings.extend(scan_terraform_text("snippet.tf", raw_tf))

            if raw_sql and "postgres-locks" in scan_types:
                all_findings.extend(scan_postgres_text("migration.sql", raw_sql))

            if raw_code and "owasp-security" in scan_types:
                all_findings.extend(scan_security_text("app_route.ts", raw_code))

            # Push findings to Apify Default Dataset
            Actor.log.info(f"Scan complete. Total findings: {len(all_findings)}")
            for item in all_findings:
                await Actor.push_data(item)
                try:
                    await Actor.charge(event_name="apify-default-dataset-item", count=1)
                except Exception:
                    pass

            # Generate Markdown Summary for Key-Value Store
            summary_md = f"# DevOps & Cloud Code Auditor Report\n\n"
            summary_md += f"**Total Findings:** {len(all_findings)}\n\n"
            if not all_findings:
                summary_md += "✅ **No architectural cost smells, locking migrations, or OWASP anti-patterns detected.**\n"
            else:
                summary_md += "| Suite | Severity | Rule | Location | Description |\n"
                summary_md += "| :--- | :--- | :--- | :--- | :--- |\n"
                for f in all_findings:
                    summary_md += f"| {f.get('suite')} | **{f.get('severity', '').upper()}** | `{f.get('rule')}` | `{f.get('file')}:{f.get('line', 0)}` | {f.get('message')} |\n"

            await Actor.set_value("OUTPUT", summary_md, content_type="text/markdown")

        finally:
            if temp_dir and os.path.exists(temp_dir):
                shutil.rmtree(temp_dir, ignore_errors=True)


if __name__ == "__main__":
    asyncio.run(main())
