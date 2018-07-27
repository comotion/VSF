// todo: block CRLF (+Set-Cookies)


sub vcl_recv {
    # Bad User-Agent - Scanners
    # - http://mod-security.svn.sourceforge.net/ (modsecurity_35_scanners.data)
    if (req.http.User-Agent ~ "(?i:(?:^(grabber|bsqlbf|mozilla\/4\.0 (compatible)|sqlmap|mozilla\/4\.0 (compatible; msie 6.0; win32)|mozilla\/5\.0 sf\/\/|arachni|sql power injector|absinthe|netsparker|python-httplib2|dirbuster|pangolin|nmap nse|sqlninja|grendel-scan|havij|w3af|hydra|nstalker|n-stalker|openvas|fimap|yanga|url_spider_sql|topblogsinfo|purebot|jikespider|google_three_web|aboundexbot|mozilla\/the mole|themole\.nasel\.com\.ar|metis|bilbo|n-stealth|black widow|brutus|cgichk|webtrends security|jaascois|pmafind|\.nasl|nsauditor|paros|nessus|nikto|webinspect|blackwidow)$))") {
        set req.http.X-VSF-RuleName = "Bad User-Agent - Scanner";
        set req.http.X-VSF-RuleID = "generic.badua-1";
        call sec_handler;
    }

    # SSI Injection
    # - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
    if (req.url ~ "(?i)(<|%3C|)(\s|%20|\t|%09|\+)*(!|%21)--(\s|%20|\t|%09|\+)*(#|%23)(\s|%20|\t|%09|\+)*(e(cho|xec)|printenv|include|cmd)") {
        set req.http.X-VSF-RuleName = "SSI Injection";
        set req.http.X-VSF-RuleID = "generic.ssi-1";
        call sec_handler;
    }

    if (req.http.X-VSF-Body) {
        # SSI Injection
        # - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
        if (req.http.X-VSF-Body ~ "(?i)(<|%3C|)(\s|%20|\t|%09|\+)*(!|%21)--(\s|%20|\t|%09|\+)*(#|%23)(\s|%20|\t|%09|\+)*(e(cho|xec)|printenv|include|cmd)") {
            set req.http.X-VSF-RuleName = "SSI Injection";
            set req.http.X-VSF-RuleID = "generic.ssi-2";
            call sec_handler;
        }
    }
}
