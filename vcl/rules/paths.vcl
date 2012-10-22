sub vcl_recv {
	# Directory traversal
	if (req.url ~ "(?i)((/|\\)\.{2}|\.{2}(/|\\))") {
		set req.http.X-VSF-RuleName = "Directory Traversal";
		set req.http.X-VSF-RuleID = "path.travers-1";
		call sec_handler;
	}

	# Web server internal files
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)\.(htaccess|htpasswd)") {
		set req.http.X-VSF-RuleName = "Web Server Internal File";
		set req.http.X-VSF-RuleID = "path.httpd-1";
		call sec_handler;
	}

	# CSM's internal files
	if (req.url ~ "(?i)\.(cvs|svn|git|hg)") {
		set req.http.X-VSF-RuleName = "CSM Internal File";
		set req.http.X-VSF-RuleID = "path.csm-2";
		call sec_handler;
	}

	# Database files
	if (req.url ~ "(?i)\.(sql|sqlite|mdb)") {
		set req.http.X-VSF-RuleName = "Database File";
		set req.http.X-VSF-RuleID = "path.sql-1";
		call sec_handler;
	}

	# Unix directories
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	#if (req.url ~ "(?i)/(etc|usr|var|tmp|local|bin|sbin|dev|boot|lib(64)?|mnt|root|boot|proc)") {
	#	set req.http.X-VSF-RuleName = "Unix Directory";
	#	set req.http.X-VSF-RuleID = "path.unix-1";
	#	call sec_handler;
	#}

	# Unix files
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)(\.((bash_)?history|(vim|bash)rc|ssh)|authorized_keys)") {
		set req.http.X-VSF-RuleName = "Unix File";
		set req.http.X-VSF-RuleID = "path.unix-2";
		call sec_handler;
	}

	# Windows partitions
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)[a-z]\:\\") {
		set req.http.X-VSF-RuleName = "Windows Partition";
		set req.http.X-VSF-RuleID = "path.win-1";
		call sec_handler;
	}

	# Windows files
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)((cmd(32)?|nc|net|telnet|wsh|ftp|nmap)\.exe|\.(db|com|bat|reg|asa))") {
		set req.http.X-VSF-RuleName = "Windows File";
		set req.http.X-VSF-RuleID = "path.win-2";
		call sec_handler;
	}

	# Bad file extensions
	# - http://mod-security.svn.sourceforge.net/ (modsecurity_crs_40_generic_attacks.conf)
	if (req.url ~ "(?i)\.(inc|ini|scr)") {
		set req.http.X-VSF-RuleName = "Bad File Extension";
		set req.http.X-VSF-RuleID = "path.generic-1";
		call sec_handler;
	}
}
