
# For now
sub sec_request_sev1 {
   set req.http.X-VSF-Severity = "1";
   call sec_handler;
}

# Checks if someone tries use a blacklisted request method
sub vcl_recv {
   set req.http.X-VSF-Module =  "request";


   if ( req.request == "PUT"
#     || req.request == "POST"
      || req.request == "TRACE"
      || req.request == "OPTIONS"
      || req.request == "CONNECT"
      || req.request == "DELETE") {
                set req.http.X-VSF-RuleName = "Blocked request methods";
                set req.http.X-VSF-RuleID   = "1";
                set req.http.X-VSF-RuleInfo = "Checks if someone tries use a blacklisted request method";
                call sec_request_sev1;
   }

   # request whitelist - this is strict and will break any non-conformant app
   if (req.request != "GET"
      && req.request != "POST"
      && req.request != "HEAD"){
                set req.http.X-VSF-RuleName = "Not in method whitelist";
                set req.http.X-VSF-RuleID   = "2";
      call sec_request_sev1;
   }
   if (req.proto ~ "^HTTP/1.1$" && !req.http.host) {
      set req.http.X-VSF-RuleName = "HTTP/1.1 no host header";
      set req.http.X-VSF-RuleID = "3";
   }
   #if (req.proto ~ "^HTTP/1.0$" && req.http.) {A
   # awaiting vmod to iterate over headers...
}
