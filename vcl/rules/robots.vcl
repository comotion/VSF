sub vcl_recv {
   set req.http.X-VSF-Module = "robots";
   if(req.url ~ "^/robots.txt$"){
      set req.http.X-VSF-RuleName = "Indexing robot : /robots.txt";
      set req.http.X-VSF-RuleID = "1";
      set req.http.X-VSF-RuleInfo = "Hostile response for robots.";
      # I will index myself thanks
      set req.http.X-Robot = req.http.User-agent + " " + client.ip;
      call sec_robot;
   }
}

# implements a handler
sub sec_robot {
  # not today
  set req.http.X-VSF-Response = {"User-agent: *
Disallow: /
"};
   error 808 "Warning robatas";
}

sub vcl_deliver {
   if(req.http.X-Robot){
      # can also fuck around with headers here
      set req.http.X-Booyah = "t3h h8z zeeke";
      unset resp.http.content-length;
   }
}

