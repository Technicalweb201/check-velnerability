const axios = require('axios');
const https = require('https');

const checkCryptographicFailures = async (targetUrl) => {
    const results = [];
    console.log(`Scanning ${targetUrl} for checkCryptographicFailures vulnerabilities...`);


    // Check if HTTPS is enforced
    if (!targetUrl.startsWith("https://")) {
        results.push({
            issue: 'Insecure Transmission',
            description: 'The website does not enforce HTTPS, which can expose data to interception.'
        });
    }

    try {
        const agent = new https.Agent({ rejectUnauthorized: false });
        const response = await axios.get(targetUrl, { httpsAgent: agent });
        const headers = response.headers;

        // Check for missing HSTS header
        if (!headers['strict-transport-security']) {
            results.push({
                issue: 'Missing HSTS Header',
                description: 'HTTP Strict Transport Security (HSTS) header is missing, which can allow SSL stripping attacks.'
            });
        }

        // Example: Check for weak or outdated TLS versions (extend as needed)
        if (response.request.res.socket.getProtocol().includes('TLSv1.0') || response.request.res.socket.getProtocol().includes('TLSv1.1')) {
            results.push({
                issue: 'Outdated TLS Version',
                description: 'The website uses outdated TLS versions. Use TLS 1.2 or higher.'
            });
        }

        // Example: Check for weak or outdated ciphers (extend as needed)
        if (response.data.toLowerCase().includes('weak-cipher')) {
            results.push({
                issue: 'Weak Cipher Suite Detected',
                description: 'The website uses weak or outdated cipher suites for encryption.'
            });
        }

        // Check for other essential security headers
        const essentialHeaders = {
            'content-security-policy': 'Content Security Policy (CSP) header missing.',
            'x-content-type-options': 'X-Content-Type-Options header missing.',
            'x-frame-options': 'X-Frame-Options header missing.',
            'x-xss-protection': 'X-XSS-Protection header missing.'
        };

        for (const [header, description] of Object.entries(essentialHeaders)) {
            if (!(header in headers)) {
                results.push({
                    issue: 'Missing Security Header',
                    header,
                    description
                });
            }
        }

        // Check for insecure cookies
        if (headers['set-cookie']) {
            headers['set-cookie'].forEach(cookie => {
                if (!cookie.toLowerCase().includes('secure') || !cookie.toLowerCase().includes('httponly')) {
                    results.push({
                        issue: 'Insecure Cookie',
                        cookie,
                        description: 'Cookies should be marked as Secure and HttpOnly to prevent exposure.'
                    });
                }
            });
        }

    } catch (error) {
        console.error(`Error accessing ${targetUrl}: ${error.message}`);
    }

    return results;
};

module.exports = {
    checkCryptographicFailures
};
