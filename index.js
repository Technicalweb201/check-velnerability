const express = require('express');
const cors = require('cors');
const { scanXssWebsite } = require('./services/xss');
const { scanSqlWebsite } = require('./services/sql');
const { checkMisconfigurations } = require('./services/misconfigurations');
const {checkBrokenAccessControl} = require('./services/brokenAccessControl')
const { checkBrokenAuthentication } = require('./services/brokenAuthentication');
const { checkIdentificationAuthentication } = require('./services/identificationAuthentication');
const { checkInsecureDesign } = require('./services/insecureDesign');
const { checkCryptographicFailures } = require('./services/cryptographicFailures');
const { checkIntegrityFailures } = require('./services/integrityFailures');




const app = express();
app.use(express.json());
app.use(cors());

app.post('/scan', async (req, res) => {
    const { targetUrl, checks } = req.body;

    if (!targetUrl) {
        return res.status(400).json({ error: 'Target URL is required' });
    }

    try {
        const scanPromises = [];

        if (checks.includes("XSS")) {
            scanPromises.push(scanXssWebsite(targetUrl));
        }

        if (checks.includes("SQL Injection")) {
            scanPromises.push(scanSqlWebsite(targetUrl));
        }

        scanPromises.push(checkMisconfigurations(targetUrl));
        if (checks.includes("Server Misconfigurations")) {
        }
        if (checks.includes("Broken Access Control")) {
            scanPromises.push(checkBrokenAccessControl(targetUrl));
        } 
        if (checks.includes("Broken Authentication")) {
            scanPromises.push(checkBrokenAuthentication(targetUrl));
        }
        if (checks.includes("Identification and Authentication Failures")) {
            scanPromises.push(checkIdentificationAuthentication(targetUrl));
        }
        if (checks.includes("Insecure Design")) {
            scanPromises.push(checkInsecureDesign(targetUrl));
        }
        if (checks.includes("Cryptographic Failures")) {
            scanPromises.push(checkCryptographicFailures(targetUrl));
        }
        if (checks.includes("Integrity Failures")) {
            scanPromises.push(checkIntegrityFailures(targetUrl));
        }
        

        const [
            xssVulnerabilities = [],
            sqlVulnerabilities = [],
            misconfigurationVulnerabilities = [],
            brokenAccessControlVulnerabilities = [],
            brokenAuthenticationVulnerabilities = [],
            identificationAuthenticationVulnerabilities = [],
            insecureDesignVulnerabilities = [],
            cryptographicFailuresVulnerabilities = [],
            integrityFailuresVulnerabilities = []
        ] = await Promise.all(scanPromises);

        const results = {
            xssVulnerabilities,
            sqlVulnerabilities,
            misconfigurationVulnerabilities,
            brokenAccessControlVulnerabilities,
            brokenAuthenticationVulnerabilities,
            identificationAuthenticationVulnerabilities,
            insecureDesignVulnerabilities,
            cryptographicFailuresVulnerabilities,
            integrityFailuresVulnerabilities
        };

        res.json({ vulnerabilities: results });
    } catch (error) {
        res.status(500).json({ error: error.message });
    }
});

app.get('/', (req, res) => {
    res.json({ message: "The server is running..." });
});

app.listen(8080, () => {
    console.log('The server is running on port 8080...');
});
