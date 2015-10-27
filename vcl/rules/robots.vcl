/* robots sometimes check robots.txt and usually do not send accept headers */
sub vcl_recv {
   set req.http.X-VSF-Module = "robots";
   if(req.url ~ "^/robots.txt$" || !req.http.accept){
      set req.http.X-VSF-RuleName = "Indexing robot : /robots.txt";
      set req.http.X-VSF-RuleID = "1";
      set req.http.X-VSF-RuleInfo = "Hostile response for robots.";
      # I will index myself thanks
      set req.http.X-Robot = req.http.User-agent + " " + client.ip;
      call sec_robots_are_ok;
   }
}

# implements a handler
sub sec_robot {
    # This just returns a static robots.txt
    set req.http.X-VSF-Response = 
		{"User-agent: *
Disallow: / "};
    return (synth(808,"Warning robatas"));
}

sub sec_robots_are_ok {
	/* do nothing really */
	std.log("robot identified: "  + req.http.user-agent);
}

sub vcl_deliver {
   if(req.http.X-Robot){
      # can also svrew around with headers here
      set req.http.X-Booyah = "t3h h8z zeeke";
   }
}

