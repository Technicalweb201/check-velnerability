const axios = require('axios');

const additionalPayloads = [
    { "username": "admin", "password": "admin123" },
    { "username": "root", "password": "root123" },
    { "username": "administrator", "password": "password" },
    { "username": "test", "password": "test" },
    { "username": "guest", "password": "guest" },
    { "username": "user", "password": "user" },
    { "username": "manager", "password": "manager" },
    { "username": "123456", "password": "123456" },
    { "username": "password", "password": "password123" },
];

const defaultAdminCredentials = [
    { "username": "admin", "password": "admin" },
    { "username": "administrator", "password": "administrator" },
    { "username": "root", "password": "root" },
];

const allPayloads = [...defaultAdminCredentials, ...additionalPayloads];

const checkBrokenAuthentication = async (targetUrl) => {
    const results = [];
    console.log(`Scanning ${targetUrl} for checkBrokenAuthentication vulnerabilities...`);
    for (const credentials of allPayloads) {
        const { username, password } = credentials;
        try {
            const response = await axios.post(targetUrl, {
                username: username,
                password: password
            });
            if (response.status === 200) {
                results.push({
                    username: username,
                    password: password,
                    status_code: response.status,
                    reason: 'Default credentials used for authentication.'
                });
            }
        } catch (error) {
            // Continue to the next credentials if there's an error
        }
    }

    return results;
};

module.exports = {
    checkBrokenAuthentication
};
