const axios = require('axios');

const checkInsecureDesign = async (targetUrl) => {
    const results = [];

    // Check for missing security headers
    console.log(`Scanning ${targetUrl} for checkInsecureDesign vulnerabilities...`);

    try {
        const response = await axios.get(targetUrl);
        const headers = response.headers;

        const securityHeaders = {
            'strict-transport-security': 'HTTP Strict Transport Security (HSTS) header missing.',
            'content-security-policy': 'Content Security Policy (CSP) header missing.',
            'x-content-type-options': 'X-Content-Type-Options header missing.',
            'x-frame-options': 'X-Frame-Options header missing.',
            'x-xss-protection': 'X-XSS-Protection header missing.'
        };

        for (const [header, description] of Object.entries(securityHeaders)) {
            if (!(header in headers)) {
                results.push({
                    issue: 'Missing Security Header',
                    header,
                    description
                });
            }
        }
    } catch (error) {
        console.error(`Error accessing ${targetUrl}: ${error.message}`);
    }

    // Check for exposed sensitive information
    const sensitiveFiles = [
        "config.json", "config.yaml", "config.yml", "config.php",
        ".env", "docker-compose.yml", "docker-compose.yaml", "wp-config.php",
        "application.properties", "application.yml", "application.yaml",
        "web.config", "settings.py", "local.settings.json"
    ];

    for (const file of sensitiveFiles) {
        const fileUrl = `${targetUrl}/${file}`;
        try {
            const response = await axios.get(fileUrl);
            if (response.status === 200) {
                results.push({
                    issue: 'Exposed Sensitive File',
                    file,
                    url: fileUrl,
                    description: 'Sensitive file exposed.'
                });
            }
        } catch (error) {
            // Continue to the next file if there's an error
        }
    }

    // Check for default credentials
    const defaultCredentials = [
        { username: "admin", password: "admin" },
        { username: "root", password: "root" },
        { username: "admin", password: "password" },
        { username: "test", password: "test" }
    ];

    for (const creds of defaultCredentials) {
        try {
            const loginData = { username: creds.username, password: creds.password };
            const response = await axios.post(targetUrl, loginData);
            if (response.status === 200) {
                results.push({
                    issue: 'Default Credentials',
                    username: creds.username,
                    password: creds.password,
                    description: 'Default credentials can be used to log in.'
                });
            }
        } catch (error) {
            // Continue to the next credentials if there's an error
        }
    }

    // Check for directory listing enabled
    try {
        const response = await axios.get(`${targetUrl}/`);
        if (response.data.includes("Index of /")) {
            results.push({
                issue: 'Directory Listing Enabled',
                url: `${targetUrl}/`,
                description: 'Directory listing is enabled, exposing contents.'
            });
        }
    } catch (error) {
        // Continue if there's an error
    }

    // Check for improper error handling exposing stack traces
    try {
        const response = await axios.get(`${targetUrl}/nonexistentpage`);
        if (response.data.toLowerCase().includes("stack trace") || response.data.toLowerCase().includes("exception")) {
            results.push({
                issue: 'Improper Error Handling',
                url: `${targetUrl}/nonexistentpage`,
                description: 'Stack trace or exception details exposed in error response.'
            });
        }
    } catch (error) {
        // Continue if there's an error
    }

    return results;
};

module.exports = {
    checkInsecureDesign
};
