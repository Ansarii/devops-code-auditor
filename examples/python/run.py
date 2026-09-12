import os
from apify_client import ApifyClient

# 1. Initialize ApifyClient (pass your API token or set APIFY_TOKEN env var)
client = ApifyClient(os.getenv("APIFY_TOKEN"))

# 2. Configure input
run_input = {'rawSql': 'CREATE INDEX idx_users_email ON users (email);', 'scanTypes': ['postgres-locks']}

# 3. Call Actor on Apify Cloud
print("Starting Actor neon_innovation_lab/devops-code-auditor on Apify Cloud...")
run = client.actor("neon_innovation_lab/devops-code-auditor").call(run_input=run_input)

# 4. Stream results from default dataset
print(f"Run finished with status: {run['status']}. Fetching results...")
for item in client.dataset(run["defaultDatasetId"]).iterate_items():
    print(item)
