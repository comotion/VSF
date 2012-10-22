
/* Security.VCL demonstration rules
 * Copyright (C) 2009 Redpill Linpro AS
 * Author: Kristian Lyngstøl <kristian@redpill-linpro.com>
 *
 * This file demonstrates the intended use of Security VCL for
 * rule-matching and how to handle the fallout.
 */

sub sec_demo_sev1 {
	set req.http.X-VSF-Severity = "1";
	call sec_handler;
}

sub vcl_recv {
	set req.http.X-VSF-Module =  "demo";

	if (req.url ~ "/exploit/") {
		//TEST:demo-1:GET:/exploit/foo/bar:bla
		//TESTN:demo-1:GET:/notexploit/foo/bar
		set req.http.X-VSF-RuleName = "Awsome demo for Security.VCL";
		set req.http.X-VSF-RuleID = "1";
		set req.http.X-VSF-RuleInfo = "This rule triggers when an 31337 h4x0r accesses a dir with name /exploit/";
		call sec_demo_sev1;
	}
}

/* vim: set syntax=c tw=76: */
