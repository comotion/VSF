sub vcl_recv {
	# TODO:
	# <body>, <html>, <style>, <layer>, <link>, <ilayer>, <meta>

	if (!req.http.X-VSF-Static) {
		if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*((V|%[57]6)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*|(J|%[46]A)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(V|%[57]6)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*)?(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)((\s|%20|\t|%09|\+)*P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-1";
			call sec_handler;
		}

		if (req.url ~ "(?i)(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)(\s|%20|\t|%09|\+)*(>|%3E)") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-2";
			call sec_handler;
		}

		if (req.url ~ "(?i)((V|%[57]6)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*|(J|%[46]A)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(V|%[57]6)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*)?(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)(\s|%20|\t|%09|\+)*(:|%3A)[^&](\(|%28)") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-3";
			call sec_handler;
		}

		if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(O|%[46]F)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*(J|%[46]A)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-4";
			call sec_handler;
		}

		if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(L|%[46]C)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-5";
			call sec_handler;
		}

		if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(D|%[46]4)") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-6";
			call sec_handler;
		}

		if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*((I|%[46]9)(\s|%20|\t|%09|\+)*)?(F|%[46]6)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(E|%[46]5)((S|%[57]3)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(T|%[57]4))?") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-7";
			call sec_handler;
		}

		if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(G|%[46]7)") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-8";
			call sec_handler;
		}


		if (req.url ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(F|%[46]6)(\s|%20|\t|%09|\+)*(O|%[46]F)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(M|%[46]D)") {
			set req.http.X-VSF-RuleName = "Cross-site Scripting";
			set req.http.X-VSF-RuleID = "xss.xss-8";
			call sec_handler;
		}


		if (req.http.X-VSF-Body) {
			if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*((V|%[57]6)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*|(J|%[46]A)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(V|%[57]6)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*)?(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)((\s|%20|\t|%09|\+)*P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-9";
				call sec_handler;
			}

			if (req.http.X-VSF-Body ~ "(?i)(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)(\s|%20|\t|%09|\+)*(>|%3E)") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-10";
				call sec_handler;
			}

			if (req.http.X-VSF-Body ~ "(?i)((V|%[57]6)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*|(J|%[46]A)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(V|%[57]6)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*)?(S|%[57]3)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(T|%[57]4)(\s|%20|\t|%09|\+)*(:|%3A)[^&](\(|%28)") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-11";
				call sec_handler;
			}

			if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(O|%[46]F)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*(J|%[46]A)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(C|%[46]3)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-12";
				call sec_handler;
			}

			if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(P|%[57]0)(\s|%20|\t|%09|\+)*(L|%[46]C)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(T|%[57]4)") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-13";
				call sec_handler;
			}

			if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(B|%[46]2)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(D|%[46]4)") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-14";
				call sec_handler;
			}

			if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*((I|%[46]9)(\s|%20|\t|%09|\+)*)?(F|%[46]6)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(A|%[46]1)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(E|%[46]5)((S|%[57]3)(\s|%20|\t|%09|\+)*(E|%[46]5)(\s|%20|\t|%09|\+)*(T|%[57]4))?") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-15";
				call sec_handler;
			}

			if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(I|%[46]9)(\s|%20|\t|%09|\+)*(M|%[46]D)(\s|%20|\t|%09|\+)*(G|%[46]7)") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-16";
				call sec_handler;
			}


			if (req.http.X-VSF-Body ~ "(?i)(<|%3C)(\s|%20|\t|%09|\+)*(/|%2f)?(\s|%20|\t|%09|\+)*(F|%[46]6)(\s|%20|\t|%09|\+)*(O|%[46]F)(\s|%20|\t|%09|\+)*(R|%[57]2)(\s|%20|\t|%09|\+)*(M|%[46]D)") {
				set req.http.X-VSF-RuleName = "Cross-site Scripting";
				set req.http.X-VSF-RuleID = "xss.xss-17";
				call sec_handler;
			}

		}
	}
}
