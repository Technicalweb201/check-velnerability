const axios = require('axios');

const MISCONFIGURATION_PATHS = [
    ".env",
    "config.php",
    "web.config",
    "phpinfo.php",
    "backup.zip",
    "db_backup.sql",
    "admin/",
    "test/",
    "debug/",
    ".git/",
    ".svn/",
    "wp-config.php",
    "logs/",
    "cgi-bin/",
    "backup/",
    "bak/",
    "temp/",
    "tmp/",
    "old/",
    "private/",
    "secret/",
    "hidden/",
    ".DS_Store",
    "node_modules/",
    "composer.json",
    "composer.lock",
    "package.json",
    "package-lock.json",
    "yarn.lock",
    "server-status",
    "server-info",
    "error_log",
    "access_log",
    "info.php",
    "phpinfo.php",
    "index.php~",
    "index.php.bak",
    "index.php.save",
    "index.html~",
    "index.html.bak",
    "index.html.save",
    "index.asp.bak",
    "index.aspx.bak",
    "index.jsp.bak",
    "index.jsp.save",
    ".htpasswd",
    ".htaccess",
    ".bash_history",
    ".ssh/",
    "id_rsa",
    "id_rsa.pub"
];

const checkMisconfigurations = async (targetUrl) => {
    const results = [];
    console.log(`Scanning ${targetUrl} for misconf vulnerabilities...`);

    for (const path of MISCONFIGURATION_PATHS) {
        const url = `${targetUrl.replace(/\/+$/, '')}/${path}`;
        try {
            const response = await axios.get(url);
            if (response.status === 200) {
                results.push({
                    url: url,
                    status_code: response.status,
                    reason: 'Potentially sensitive file or directory exposed.'
                });
            }
        } catch (error) {
            // Continue without logging the error
        }
    }
    return results;
};

module.exports = {
    checkMisconfigurations
};
