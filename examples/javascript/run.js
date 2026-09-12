import { ApifyClient } from 'apify-client';

// 1. Initialize client
const client = new ApifyClient({
    token: process.env.APIFY_TOKEN,
});

const input = {'rawSql': 'CREATE INDEX idx_users_email ON users (email);', 'scanTypes': ['postgres-locks']};

(async () => {
    console.log('Starting Actor neon_innovation_lab/devops-code-auditor on Apify Cloud...');
    const run = await client.actor('neon_innovation_lab/devops-code-auditor').call(input);
    
    console.log();
    const { items } = await client.dataset(run.defaultDatasetId).listItems();
    console.dir(items, { depth: null });
})();
