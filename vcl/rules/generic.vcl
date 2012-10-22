// todo: block CRLF (+Set-Cookies)


sub vcl_recv {
	# Bad User-Agent - Scanners
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_35_scanners.data)
	if (req.http.User-Agent ~ "(i)(metis|bilbo|n-stealth|black widow|brutus|cgichk|webtrends security|jaascois|pmafind|\.nasl|nsauditor|paros|nessus|nikto|webinspect|blackwidow)") {
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
