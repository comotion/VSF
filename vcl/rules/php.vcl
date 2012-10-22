
# For now
sub sec_php_sev1 {
        set req.http.X-VSF-Severity = "1";
        call sec_handler;
}


sub vcl_recv {
        set req.http.X-VSF-Module =  "php";

        # Checks if someone tries to alter predefined $GLOBALS variable via url
        if (req.url ~ "GLOBALS\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable GLOBALS";
                set req.http.X-VSF-RuleID   = "1";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: GLOBALS";
                call sec_php_sev1;
        }

        # Checks if someone tries to alter predefined _SERVER variable via url
        if (req.url ~ "_SERVER\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _SERVER";
                set req.http.X-VSF-RuleID   = "2";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _SERVER";
                call sec_php_sev1;
        }

        # Checks if someone tries to alter predefined _GET variable via url
        if (req.url ~ "_GET\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _GET";
                set req.http.X-VSF-RuleID   = "3";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _GET";
                call sec_php_sev1;
        }

        # Checks if someone tries to alter predefined _POST variable via url
        if (req.url ~ "_POST\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _POST";
                set req.http.X-VSF-RuleID   = "4";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _POST";
                call sec_php_sev1;
        }

        # Checks if someone tries to alter predefined _FILE variable via url
        if (req.url ~ "_FILES\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _FILES";
                set req.http.X-VSF-RuleID   = "5";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _FILES";
                call sec_php_sev1;
        }
 
        # Checks if someone tries to alter predefined _REQUEST variable via url
        if (req.url ~ "_REQUEST\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _REQUEST";
                set req.http.X-VSF-RuleID   = "6";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _REQUEST";
                call sec_php_sev1;
        }
 
        # Checks if someone tries to alter predefined _SESSION variable via url
        if (req.url ~ "_SESSION\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _SESSION";
                set req.http.X-VSF-RuleID   = "7";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _SESSION";
                call sec_php_sev1;
        }

        # Checks if someone tries to alter predefined _ENV variable via url
        if (req.url ~ "_ENV\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _ENV";
                set req.http.X-VSF-RuleID   = "8";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _ENV";
                call sec_php_sev1;
        }

        # Checks if someone tries to alter predefined _COOKIE variable via url
        if (req.url ~ "_COOKIE\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _COOKIE";
                set req.http.X-VSF-RuleID   = "9";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _COOKIE";
                call sec_php_sev1;
        }

        # Checks if someone tries to alter predefined _REQUEST variable via url
        if (req.url ~ "_REQUEST\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _REQUEST";
                set req.http.X-VSF-RuleID   = "8";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _REQUEST";
                call sec_php_sev1;
        }

        if (req.url ~ "_PHPLIB\[") {
                set req.http.X-VSF-RuleName = "Manipulation of Predefined Variable _PHPLIB";
                set req.http.X-VSF-RuleID   = "13";
                set req.http.X-VSF-RuleInfo = "Manipulation of Predefined Variable: _PHPLIB";
                call sec_php_sev1;
        }

# One could make one long regexp with common php statements. For now:

        # Generic check for code execution
        if (req.url ~ "system\(") {
                set req.http.X-VSF-RuleName = "PHP command: system()";
                set req.http.X-VSF-RuleID   = "9";
                set req.http.X-VSF-RuleInfo = "Generic check for PHP commands in URL: system()";
                call sec_php_sev1;
        }

        # Generic check for code execution
        if (req.url ~ "passthru\(") {
                set req.http.X-VSF-RuleName = "PHP command: passthru()";
                set req.http.X-VSF-RuleID   = "10";
                set req.http.X-VSF-RuleInfo = "Generic check for PHP commands in URL: passthru()";
                call sec_php_sev1;
        }

        # Generic check for code execution
        if (req.url ~ "eval\(") {
                set req.http.X-VSF-RuleName = "PHP command: eval()";
                set req.http.X-VSF-RuleID   = "11";
                set req.http.X-VSF-RuleInfo = "Generic check for PHP commands in URL: eval()";
                call sec_php_sev1;
        }

        # Generic check for PHP code inclusion in URL
        if (req.url ~ "(<|\%3C)?\?(php)?.*(php)?\?(>|\%3E)?") {
                set req.http.X-VSF-RuleName = "PHP code inclusion in URL: <?php ..code.. ?>";
                set req.http.X-VSF-RuleID   = "12";
                set req.http.X-VSF-RuleInfo = "Generic check for PHP code in URL: <?php ..code.. ?>";
                call sec_php_sev1;
        }

        # Generic check for remote code inclusion from external sites
        if (req.url ~ "=?(https?|ftps?|php)://") {
                set req.http.X-VSF-RuleName = "Remote site in URL parameter";
                set req.http.X-VSF-RuleID   = "100";
                set req.http.X-VSF-RuleInfo = "Generic check for remote code inclusion from external sites";
                call sec_php_sev1;
        }

}
