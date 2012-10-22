
# For now
sub sec_localfiles_sev1 {
        set req.http.X-VSF-Severity = "1";
        call sec_handler;
}


sub vcl_recv {
        set req.http.X-VSF-Module =  "localfiles";

        # Checks if someone tries to access common files from /etc/ dir
        if (req.url ~ "/etc/(passwd(\-)?|(g)?shadow(\-)?|motd|group(\-)?)") {
                set req.http.X-VSF-RuleName = "Local file access attempt in: /etc/";
                set req.http.X-VSF-RuleID   = "1";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to access known local files in: /etc/";
                call sec_localfiles_sev1;
        }

        # Checks if someone tries to access common dirs in /etc/ dir
        if (req.url ~ "/etc/(apache(2)?|httpd|phpmyadmin|mysql|php(4|5)?)/") {
                set req.http.X-VSF-RuleName = "Local dir access attempt in: /etc/";
                set req.http.X-VSF-RuleID   = "2";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to access known local directories in: /etc/";
                call sec_localfiles_sev1;
        }

        # Checks if someone tries to access /tmp/ dir
        if (req.url ~ "/tmp/") {
                set req.http.X-VSF-RuleName = "Local dir access attempt: /tmp/";
                set req.http.X-VSF-RuleID   = "3";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries access a local directory: /tmp/";
                call sec_localfiles_sev1;
        }

        # Checks if someone tries to access common dirs in /var/ dir
        if (req.url ~ "/var/(log|backups|mail|www)/") {
                set req.http.X-VSF-RuleName = "Local dir access attempt in: /var/";
                set req.http.X-VSF-RuleID   = "4";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries access a local directory in: /var/";
                call sec_localfiles_sev1;
        }

        # Checks if someone tries to access common files from /proc/ dir
        if (req.url ~ "/proc/(self/environ|cmdline|cpuinfo|mounts|mdstat|partitions|version(_signature)?|uptime)") {
                set req.http.X-VSF-RuleName = "Local file access attempt in: /proc/";
                set req.http.X-VSF-RuleID   = "5";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to access known local files in: /proc/";
                call sec_localfiles_sev1;
        }

        # Checks if someone tries a directory traversal
        if (req.url ~ "\.(\.)?/\.(\.)?/\.(\.)?") {
                set req.http.X-VSF-RuleName = "Directory traversal attempt: ../../.. or ././../ etc";
                set req.http.X-VSF-RuleID   = "6";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries a directory traversal of more than 3 dirs";
                call sec_localfiles_sev1;
        }

}
