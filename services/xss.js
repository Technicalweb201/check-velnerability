const axios = require('axios');
const {xssPayloads} =require('./payloads/payload')



// Function to check for XSS vulnerabilities
async function checkXSS(url) {
    const vulnerabilities = [];

    for (const payload of xssPayloads) {
        const encodedPayload = encodeURIComponent(payload);
        const testUrl = `${url}?q=${encodedPayload}`;
        
        try {
            const response = await axios.get(testUrl, {
                headers: {
                    'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/58.0.3029.110 Safari/537.3'
                }
            });
            
            if (response.data.includes(payload)) {
                vulnerabilities.push({
                    url: testUrl,
                    payload: payload
                });
            }
        } catch (error) {
            // console.error(`Error requesting ${testUrl}:`, error);
        }
    }

    return vulnerabilities;
}

async function scanXssWebsite(baseUrl) {
    console.log(`Scanning ${baseUrl} for XSS vulnerabilities...`);
    const vulnerabilities = await checkXSS(baseUrl);
    
    return vulnerabilities;
}

module.exports = {
    scanXssWebsite,
    checkXSS
};
