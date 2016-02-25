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

sub sec_default_handler {
    # swap this one with your handler (see below)
    call sec_reject;

    #call sec_passthru;  #      do nothing but log the rule and deliver the request
    #call sec_general;   # 800  # debug handler - delivers X-VSF-Rule to client
    #call sec_reject;    # 801  # 403 reject with message
    #call sec_redirect;  # 802  # 302 redirect
    #call sec_honeypot;  # 803  # restart request with honeypot backend
    #call sec_synthtml;  # 804  # synthesize a response
    #call sec_drop;      # 805  # drop the request (not implemented)
    #call sec_myhandler; # any  # do your own thing (as below)
}

# Here you can specify what gets logged when a rule triggers.
sub sec_log {
    std.log("security.vcl alert xid:" + req.xid + " " + req.proto
        + " [" + req.http.X-VSF-Module + "-" + req.http.X-VSF-RuleID + "]"
        + req.http.X-VSF-Client
        + " (" +  req.http.X-VSF-RuleName + ") ");
    #std.syslog(6, "<VSF> " + std.time2real(now) + " [" + req.http.X-VSF-RuleName + "/ruleid:" + req.http.X-VSF-RuleID + "]: " + req.http.X-VSF-ClientIP + " - " + req.http.X-VSF-Method + " http://" + req.http.X-VSF-URL + " " + req.http.X-VSF-Proto + " - " + req.http.X-VSF-UA);
}


/* You can define your own handlers here if you know a little vcl.
 * The default handlers are defined in main.vcl
 * remember that it must be referenced in the code above */

/* sample handler, contains sample code for all handler types */
sub sec_myhandler {
    # perform an action based on the error code as above.

    return (synth(800, "Blahblah")); # debug response

    set req.http.X-VSF-Response = "we don't like your kind around here";
    return (synth(801, "Rejected"));

    set req.http.X-VSF-Response = "http://u.rdir.it/hit/me/please";
    return (synth(802, "Redirect"));

    # send to sec_honey backend
    return (synth(803, "Honeypot me"));

    set req.http.X-VSF-Response = "<h1>Whatever</h1> so you think you can dance?";
    return (synth(804, "Synthesize"));

    return (synth(805, "Drop"));
}


