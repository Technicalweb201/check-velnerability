
const axios = require('axios')
const {sqlPayloads} =require('./payloads/payload')



const checkSqlInjection = async (url) => {
    const vulnerabilities = [];

    for (const payload of sqlPayloads) {
        const testUrl = `${url}?q=${encodeURIComponent(payload)}`;

        try {
            const response = await axios.get(testUrl);
            if (response.data.toLowerCase().includes('error') || response.data.toLowerCase().includes('syntax')) {
                vulnerabilities.push({
                    url: testUrl,
                    payload: payload
                });
            }
        } catch (error) {
            // console.error(`Error requesting ${testUrl}: ${error.message}`);
        }
    }

    return vulnerabilities;
};



const scanSqlWebsite = async (baseUrl) => {
    console.log(`Scanning ${baseUrl} for SQL injection vulnerabilities...`);
    const vulnerabilities = await checkSqlInjection(baseUrl);
    return vulnerabilities;
};

module.exports = {
    scanSqlWebsite
}