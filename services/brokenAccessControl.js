const axios = require('axios');

const BROKEN_ACCESS_CONTROL_PATHS = [
    "admin/",
    "admin.php",
    "admin/login",
    "admin/dashboard",
    "admin/panel",
    "admin/config",
    "user/profile",
    "user/settings",
    "api/admin/",
    "api/users",
    "api/users/1",
    "api/settings",
    "api/config",
    "api/admin/config",
    "admin/backup",
    "backup/",
    "db_backup.sql",
    "private/",
    "secret/",
    "hidden/",
    ".env",
    ".git/",
    ".svn/",
    "config/",
    "config.json",
    "config.yaml",
    "config.xml",
    "config.php",
    "settings/",
    "settings.php",
    "settings.json",
    "settings.yaml",
    "logs/",
    "log.txt",
    "error.log",
    "access.log",
    "admin_console/",
    "console/",
    "admin_tools/",
    "tools/",
    "scripts/",
    "script.php",
    "script.sh",
    "cmd/",
    "command/",
    "execute/",
    "debug/",
    "test/",
    "testing/",
    "staging/",
    "dev/",
    "development/",
    "qa/",
    "qa_test/",
    "beta/",
    "beta_test/",
    "sandbox/",
    "sandbox_test/",
    "monitor/",
    "monitoring/",
    "stat/",
    "statistics/",
    "statistic/",
    "report/",
    "reporting/",
    "secure/",
    "secured/",
    "sensitive/",
    "hidden_files/",
    "private_files/",
    "public/",
    "public_files/",
    "uploads/",
    "upload/",
    "downloads/",
    "download/"
];

const checkBrokenAccessControl = async (targetUrl) => {
    const results = [];
    console.log(`Scanning ${targetUrl} for brokenaccesscontrol vulnerabilities...`);
    for (const path of BROKEN_ACCESS_CONTROL_PATHS) {
        const url = `${targetUrl.replace(/\/$/, '')}/${path}`;
        try {
            const response = await axios.get(url);
            if (response.status === 200) {
                results.push({
                    url: url,
                    status_code: response.status,
                    reason: 'Access control vulnerability detected - accessible without authentication.'
                });
            } else if ([403, 401].includes(response.status)) {
                results.push({
                    url: url,
                    status_code: response.status,
                    reason: 'Proper access control in place.'
                });
            }
        } catch (error) {
            // Continue to the next URL if there's an error
        }
    }

    return results;
};

module.exports = {
    checkBrokenAccessControl
};
