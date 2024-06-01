const axios = require('axios');

const insecureTransmissionUrls = [
    "http://", "ftp://",  // Plain HTTP and FTP
];

const weakPasswords = [
    "password", "123456", "admin", "admin123", "password123",
    "qwerty", "abc123", "123456789", "password1", "12345678",
];

const checkIdentificationAuthentication = async (targetUrl) => {
    const results = [];
    console.log(`Scanning ${targetUrl} for checkIdentificationAuthentication vulnerabilities...`);
    for (const url of insecureTransmissionUrls) {
        const insecureUrl = url + targetUrl;
        try {
            const response = await axios.get(insecureUrl);
            if (response.status === 200) {
                results.push({
                    url: insecureUrl,
                    status_code: response.status,
                    reason: 'Credentials transmitted over insecure connection.'
                });
            }
        } catch (error) {
            // Continue to the next URL if there's an error
        }
    }

    for (const password of weakPasswords) {
        try {
            const loginData = { username: "admin", password: password };
            const response = await axios.post(targetUrl, loginData);
            if (response.status === 200) {
                results.push({
                    password: password,
                    status_code: response.status,
                    reason: 'Weak password policy allows authentication with common password.'
                });
            }
        } catch (error) {
            // Continue to the next password if there's an error
        }
    }

    return results;
};

module.exports = {
    checkIdentificationAuthentication
};
