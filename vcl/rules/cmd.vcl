
# For now
sub sec_cmd_sev1 {
        set req.http.X-VSF-Severity = "1";
        call sec_handler;
}


sub vcl_recv {
        set req.http.X-VSF-Module =  "cmd";

# Should it be "wget%20", "wget " or "wget\s+"  ?
# "=cmd\W+" or "=cmd.+" is the best I can think of at the moment
# What about "=cmd(\%20| )" or... ?

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)wget.+") {
                set req.http.X-VSF-RuleName = "Common command in URL: wget";
                set req.http.X-VSF-RuleID   = "1";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject a common command name in URL: wget";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)curl.+") {
                set req.http.X-VSF-RuleName = "Common command in URL: curl";
                set req.http.X-VSF-RuleID   = "2";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject a common command name in URL: curl";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)echo.+") {
                set req.http.X-VSF-RuleName = "Common command in URL: curl";
                set req.http.X-VSF-RuleID   = "3";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject a common command name in URL: curl";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)cat.+") {
                set req.http.X-VSF-RuleName = "Common command in URL: curl";
                set req.http.X-VSF-RuleID   = "4";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject a common command name in URL: curl";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&|%7C%7C)cmd.exe.+") {
                set req.http.X-VSF-RuleName = "Common command in URL: cmd.exe";
                set req.http.X-VSF-RuleID   = "5";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject a common command name in URL: cmd.exe";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&)nc(.exe)?.+(\-(l|p)?)?") {
                set req.http.X-VSF-RuleName = "Common command in URL: netcat";
                set req.http.X-VSF-RuleID   = "6";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to inject a common command name in URL: netcat";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to inject a common command name in URL
        if (req.url ~ "(=|;|&&)(whoami|who|uptime|last|df).*") {
                set req.http.X-VSF-RuleName = "Unix command in url";
                set req.http.X-VSF-RuleID   = "7";
                set req.http.X-VSF-RuleInfo = "Triggers on unix command in URL: whoami/who/uptime/last/df";
                call sec_cmd_sev1;
        }

        # Checks if someone tries to redirect output to /dev/null
        if (req.url ~ "(>|%3E|-o)+" && req.url ~ "/dev/null") {
                set req.http.X-VSF-RuleName = "Common redirect of command ouput in URL: /dev/null";
                set req.http.X-VSF-RuleID   = "100";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries to redirect command output in URL: /dev/null";
                call sec_cmd_sev1;
        }
}
