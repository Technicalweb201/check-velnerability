const axios = require('axios');
const https = require('https');
const { JSDOM } = require('jsdom');

const checkIntegrityFailures = async (targetUrl) => {
    const results = [];
    console.log(`Scanning ${targetUrl} for checkIntegrityFailures vulnerabilities...`);

    try {
        const agent = new https.Agent({ rejectUnauthorized: false });
        const response = await axios.get(targetUrl, { httpsAgent: agent });
        const headers = response.headers;

        // Check for missing or incorrect CSP header
        if (!headers['content-security-policy']) {
            results.push({
                issue: 'Missing Content Security Policy (CSP) Header',
                description: 'The website is missing a CSP header which helps to protect against XSS and data injection attacks.'
            });
        }

        // Check for Subresource Integrity (SRI) in external scripts
        const dom = new JSDOM(response.data);
        const scripts = dom.window.document.querySelectorAll('script[src]');
        scripts.forEach(script => {
            if (!script.getAttribute('integrity')) {
                results.push({
                    issue: 'Missing Subresource Integrity (SRI)',
                    description: `The external script ${script.src} is missing SRI, which helps to ensure the integrity of the resource.`
                });
            }
        });

        // Check for exposed .git directory or backup files
        const sensitivePaths = [
            '.git/',
            '.git/config',
            'backup.sql',
            'database.sql',
            'backup.zip',
            'config.yaml',
            'config.php',
            '.env'
        ];

        for (const path of sensitivePaths) {
            const url = `${targetUrl.replace(/\/$/, '')}/${path}`;
            const sensitiveResponse = await axios.get(url, { httpsAgent: agent });
            if (sensitiveResponse.status === 200) {
                results.push({
                    issue: 'Exposed Sensitive File or Directory',
                    path: url,
                    description: 'Sensitive files or directories are exposed, which can lead to unauthorized access.'
                });
            }
        }

        // Check for default or weak admin credentials
        const adminUrls = [
            'admin',
            'administrator',
            'admin/login',
            'admin.php'
        ];
        const weakCredentials = [
            { username: 'admin', password: 'admin' },
            { username: 'admin', password: 'password' },
            { username: 'admin', password: '123456' }
        ];

        for (const adminUrl of adminUrls) {
            const url = `${targetUrl.replace(/\/$/, '')}/${adminUrl}`;
            for (const creds of weakCredentials) {
                const adminResponse = await axios.post(url, { username: creds.username, password: creds.password }, { httpsAgent: agent });
                if (adminResponse.status === 200 && adminResponse.data.toLowerCase().includes('dashboard')) {
                    results.push({
                        issue: 'Default or Weak Admin Credentials',
                        path: url,
                        description: `The website allows login with default or weak credentials: ${creds.username}/${creds.password}.`
                    });
                    break;
                }
            }
        }

    } catch (error) {
        console.error(`Error accessing ${targetUrl}: ${error.message}`);
    }

    return results;
};

module.exports = {
    checkIntegrityFailures
};
