/* Security.vcl handlers VCL file
 * Copyright (C) 2009 Kacper Wysocki
 * 
 * **************** handlers **************** *
 * The rest of the code assumes this file defines the
 * following:
 *   sec_honey   - the honeyput backend
 *   sec_log     - logging function
 *   sec_handler - this function handles all triggered rules
 *
 * If you do not intend on changing these there is no need to read on.
 */

C{
      #include <syslog.h>
}C

sub sec_default_handler {
   # swap this one with your handler (see below)
   call sec_reject;

   #call sec_general;   # 800  # debug handler - delivers X-SEC-Rule to client
   #call sec_reject;    # 801  # 403 reject with message
   #call sec_redirect;  # 802  # 302 redirect
   #call sec_honeypot;  # 803  # restart request with honeypot backend
   #call sec_synthtml;  # 804  # synthesize a response
   #call sec_drop;      # 805  # drop the request (not implemented) 
   #call sec_myhandler; # any  # do your own thing (as below)
}

/* the honeypot backend... 
 * presently defined to give no service
 * possible uses:
 *   send to less critical server
 *   log evil traffic
 *   sandbox request
 *   execute CGI scripts based on traffic
 *   ... ie to firewall client
 *   ... other active responses?
 */
backend sec_honey {
   .host = "127.0.1.2";
   .port = "3";
}

# Here you can specify what gets logged when a rule triggers.
sub sec_log {
         std.log("security.vcl alert xid:" + req.xid + " " + req.proto
             + " [" + req.http.X-SEC-Module + "-" + req.http.X-SEC-RuleId + "]"
             + req.http.X-SEC-Client
             + " (" +  req.http.X-SEC-RuleName + ") ");
         // call vsf_syslog
}

/*
sub vsf_syslog {
	C{
		syslog(LOG_INFO, "<VSF> %f [%s/ruleid:%s]: %s - %s http://%s %s - %s", VRT_r_now(sp), VRT_GetHdr(sp, HDR_REQ, "\015X-VSF-RuleName:"), VRT_GetHdr(sp, HDR_REQ, "\015X-VSF-RuleID:"), VRT_GetHdr(sp, HDR_REQ, "\017X-VSF-ClientIP:"), VRT_GetHdr(sp, HDR_REQ, "\015X-VSF-Method:"), VRT_GetHdr(sp, HDR_REQ, "\012X-VSF-URL:"), VRT_GetHdr(sp, HDR_REQ, "\014X-VSF-Proto:"), VRT_GetHdr(sp, HDR_REQ, "\011X-VSF-UA:"));
	}C
}
*/


/* You can define your own handlers here if you know a little vcl.
 * The default handlers are defined in main.vcl
 * remember that it must be referenced in the code above */

/* sample handler, contains sample code for all handler types */
sub sec_myhandler {
   # perform an action based on the error code as above.

   error 800 "Blahblah"; # debug response

   set req.http.X-SEC-Response = "we don't like your kind around here";
   error 801 "Rejected";

   set req.http.X-SEC-Response = "http://u.rdir.it/hit/me/please";
   error 802 "Redirect";

   # send to sec_honey backend
   error 803 "Honeypot me";

   set req.http.X-SEC-Response = "<h1>Whatever</h1> so you think you can dance?";
   error 804 "Synthesize";

   error 805 "Drop";
}
