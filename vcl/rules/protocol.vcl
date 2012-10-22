sub vcl_recv {
	# Allowed methods
	if (req.request != "GET" && req.request != "HEAD" && req.request != "PUT" &&
	    req.request != "POST" && req.request != "DELETE") {
		set req.http.X-VSF-RuleName = "Method Not Allowed";
		set req.http.X-VSF-RuleID = "protocol.method-1";
		call sec_handler;
	}

	# Empty Host Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_21_protocol_anomalies.conf)
	if (!req.http.host) {
		set req.http.X-VSF-RuleName = "Empty Host Header";
		set req.http.X-VSF-RuleID = "protocol.host-1";
		call sec_handler;
	}

	# Empty Accept Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_21_protocol_anomalies.conf)
	if (!req.http.Accept) {
		set req.http.X-VSF-RuleName = "Empty Accept Header";
		set req.http.X-VSF-RuleID = "protocol.accpt-1";
		call sec_handler;
	}

	# Empty User-Agent Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_21_protocol_anomalies.conf)
	if (!req.http.user-agent) {
		set req.http.X-VSF-RuleName = "Empty User-Agent Header";
		set req.http.X-VSF-RuleID = "protocol.ua-1";
		call sec_handler;
	}

	# Invalid Connection Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.bad-behavior.ioerror.us/documentation/how-it-works/ 
	if (req.http.Connection && req.http.Connection !~ "^(keep-alive|close)$") {
		set req.http.X-VSF-RuleName = "Invalid Connection Header";
		set req.http.X-VSF-RuleID = "protocol.conn-1";
		call sec_handler;
	}

	# POST without Content-Length Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.w3.org/Protocols/rfc2616/rfc2616-sec9.html#sec9.5
	if (req.request == "POST" && (!req.http.Content-Length || req.http.Content-Length ~ "^0+$")) {
		set req.http.X-VSF-RuleName = "Empty Content-Length Header";
		set req.http.X-VSF-RuleID = "protocol.clen-1";
		call sec_handler;
	}

	# Non numeric Content-Length Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.w3.org/Protocols/rfc2616/rfc2616-sec14.html#sec14.13 
	if (req.request == "POST" && req.http.Content-Length !~ "^[0-9]+$") {
		set req.http.X-VSF-RuleName = "Non numeric Content-Length Header";
		set req.http.X-VSF-RuleID = "protocol.clen-2";
		call sec_handler;
	}

	# POST without Content-Type Header
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	if (req.request == "POST" && !req.http.Content-Type) {
		set req.http.X-VSF-RuleName = "Empty Content-Type Header";
		set req.http.X-VSF-RuleID = "protocol.ctype-1";
		call sec_handler;
	}

	# Expected Header on HTTP < 1.1
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.bad-behavior.ioerror.us/documentation/how-it-works/
	if (req.http.Expect && req.proto != "HTTP/1.1") {
		set req.http.X-VSF-RuleName = "Expect Header is Allowed Only on HTTP/1.1";
		set req.http.X-VSF-RuleID = "protocol.expctd-1";
		call sec_handler;
	}

	# Pragma without Cache-Control Header on HTTP/1.1
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_20_protocol_violations.conf)
	# - http://www.bad-behavior.ioerror.us/documentation/how-it-works/
	if (req.http.Pragma && req.proto == "HTTP/1.1" && !req.http.Cache-Control) {
		set req.http.X-VSF-RuleName = "Pragma requires Cache-Control on HTTP/1.1";
		set req.http.X-VSF-RuleID = "protocol.cache-1";
		call sec_handler;
	}

	# Normalize
	if (req.http.Accept-Encoding ~ "gzip") {
		set req.http.Accept-Encoding = "gzip";
	}
	elsif (req.http.Accept-Encoding ~ "deflate") {
		set req.http.Accept-Encoding = "deflate";
	}

	if (req.http.X-VSF-Static) { 
		unset req.http.cookie;
		set req.url = regsub(req.url, "\?.*$", "");
	}
}
