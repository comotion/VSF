# comotion@krutt.org
# hide headers that would otherwise reveal varnish
# note: there are other cleverer ways of discovering varnish

# sec handler 
sub sec_cloak {
   set req.http.X-VSF-Severity = "1";
   set req.http.X-VSF-Module =  "cloak";
   std.log("cloak status: " + req.http.X-VSF-Cloak-status);

   error 801 "OK";
}


sub vcl_deliver {
   # cloak
   remove resp.http.Via;
   remove resp.http.X-Varnish;
   remove resp.http.Retry-after;
   remove resp.http.Server;
   remove resp.http.Vary;  # no leaking of vary

   # cant get rid these, they get added after deliver.
   # so much for proper cloaking
   remove resp.http.Connection; 
   
   # do some header reordering (-better support thru future vmod?)
   set req.http.co = resp.http.Connection;
   set req.http.da = resp.http.Date;
   set req.http.ct = resp.http.Content-Type;
   set req.http.cl = resp.http.Content-Length;
   if(req.proto ~ "^$"){
      # HTTP 0.9: no headers necessary, client doesn't read them anyway.
      unset resp.http.Date;
      unset resp.http.Age;
      unset resp.http.Content-Type;
      unset resp.http.Content-Length;
      unset resp.http.Connection;
      unset resp.http.Last-Modified;
      unset resp.http.Keep-Alive;
      unset resp.http.Expires;
      unset resp.http.Cache-control;
      set resp.proto = ""; # varnish will send ' 200 OK' which is a little sad...

   }elsif(req.proto ~ "HTTP/1.0"){
      set resp.http.Content-Length = req.http.cl;
      set resp.http.Content-Type = req.http.ct;
      set resp.http.Date = req.http.da;
      set resp.proto = "HTTP/1.0";
   } else {
      set resp.http.Date = req.http.da;
      set resp.http.Content-Length = req.http.cl;
      set resp.http.Content-Type = req.http.ct;
      set resp.http.Connection = req.http.co;
      set resp.proto = "HTTP/1.1";
   }
   # don't leak weird status codes
   if(resp.status != 200
      && resp.status != 404
      && resp.status != 302
      && resp.status != 501
      && resp.status != 503
      && resp.status != 302
      && resp.status != 301
      && resp.status != 304
      && (resp.status < 400 || resp.status > 405) 
      || resp.status > 503){

      # Workaround: in deliver, we can't call our handler which calls error
      set req.http.X-VSF-Cloak-status = resp.status;
      return (restart);
   }
}

sub vcl_recv {
   set req.http.X-VSF-Module = "cloak";
   
   # I'm sure there are other urls you can try Erik
   if (!req.proto ~ "^$" && ! req.proto ~ "^HTTP/1.[01]$" || req.url ~ "^/%250?$"){
      set req.http.X-VSF-RuleName = "Bogus request";
      set req.http.X-VSF-RuleID = "1";
      set req.http.X-VSF-RuleInfo = "Htrosbif specific";
      # htrosbif attacks! lets try to confuse it
      error 100 "continue";
      call sec_handler;
   }
   # we restarted from deliver, we wanted the handler
   if(req.restarts == 1 && req.http.X-VSF-Cloak-status) {
      call sec_cloak;
   }
}


# Try to obscure the client-to-backend comms as well
sub vcl_miss {
   # remove bereq.http.User-agent;
   remove bereq.http.X-Forwarded-For;
   remove bereq.http.X-Varnish;
}
