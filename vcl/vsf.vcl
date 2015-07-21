vcl 4.0;

/* VSF main VCL file
 * XXX: Paths are hardcoded, otherwise they don't resolve. sorry.
 */
import std;
import vsf;
import vsthrottle;

# clear all internal variables
include "/etc/varnish/security/build/variables.vcl";

sub vcl_recv {
    set req.http.X-VSF-ClientIP = client.ip;
    set req.http.X-VSF-Method = req.method;
    set req.http.X-VSF-Proto = req.proto;
    set req.http.X-VSF-URL = req.http.host + req.url;
    set req.http.X-VSF-UA = req.http.user-agent;
    if (req.url ~ "(i)^/[^?]+\.(css|js|jp(e)?g|ico|png|gif|txt|gz(ip)?|zip|rar|iso|lzma|bz(2)?|t(ar\.)?gz|t(ar\.)?bz)(\?.*)?$") {
        set req.http.X-VSF-Static = "y";
    } else {
        set req.http.X-VSF-URL = vsf.urldecode(req.url);
        set req.http.X-VSF-Body = vsf.body();
    }

    # gather info about client
    # this is one of the vars guaranteed to be present
    # if and only if your request is inside security.vcl
    set req.http.X-VSF-Client = "[" +  client.ip + "] "
        + req.http.host + req.url
        + " (" + req.http.user-agent + ")";
}

# which modules to use, what to log, how to handle events and honeypot
# backend definition
include "/etc/varnish/security/config.vcl";

# fallthrough: clear all internal variables on security.vcl_recv exit
include "/etc/varnish/security/build/variables.vcl";

# define all the event handlers
include "/etc/varnish/security/handlers.vcl";

/* The value of '800' and up is used because it is not actual HTTP error
 * codes. They should not be exposed.
 *
 * The list thus far:
 *  800 - Debug
 *  801 - Plain error (403-forbidden might be a bad rewrite here)
 *  802 - Redirect
 *  803 - Restart, forward to backend honey
 *  804 - Synthetic response
 *  805 - Attempt to drop or reset the request (not implemented yet)
 *  808 - Raw synthetic deliver
 */
sub vcl_synth {
    # are we insecure?
    std.log("vcl_synth");

    if (req.restarts == 0 && req.http.X-VSF-Client ) {
        # XXX: for some reason one log prints twice... bug?
        call sec_log;
        if (resp.status == 800) {
            set resp.http.X-VSF-Rule = req.http.X-VSF-Rule;
            set resp.status = 200;
        } elsif (resp.status == 801) {
            set resp.status = 403;
            if (req.http.X-VSF-Response ) {
                set resp.reason = req.http.X-VSF-Response;
            } else {
                set resp.reason = "Forbidden";
            }
        } elsif (resp.status == 802) {
            set resp.status = 302;
            #set resp.reason = "Redirected for fun and profit";
            if (resp.http.X-VSF-Response ) {
                set resp.http.Location = resp.http.X-VSF-Response;
            } else {
                set resp.http.Location =
		    "http://images.google.com/images?q=llama";
            }
            return (deliver);
        } elsif (resp.status == 803) {
            # restart on 2nd backend
            set req.http.X-VSF-Response = "honeypot me";
            set req.backend_hint = sec_honey;
            return (restart);
        } elsif (resp.status == 804) {
            set resp.status = 200;
            set resp.reason = "OK";
            set resp.http.content-type = "text/html";
            if (! resp.http.X-VSF-Response ) {
                set resp.http.X-VSF-Response = "Synthetic";
            }
            synthetic({"<html><body>
"} + resp.http.X-VSF-Response + {"
</body></html>
"});
            return (deliver);
        } elsif (resp.status == 805) {
            set resp.status = 501;
            set resp.reason = "Get outta here";
        } elsif (resp.status == 808) {
            set resp.status = 200;
            set resp.reason = "OK";
            synthetic(req.http.X-VSF-Response);
        }
        # fallthrough to other vcl_synth's
    }
}

/* Call this one to just log rule hits and pass to backend
 * without calling error.
 * This effectively *DISABLES* security.vcl protectionism */
sub sec_passthru {
    call sec_log;
}


/* Call this one for a catch-all */
sub sec_general {
    return (synth(800, "Naughty, not nice!"));
}

/* 403 rejected */
sub sec_reject {
    return (synth(801, "Rejected"));
}

/* call this one for a redirect */
sub sec_redirect {
    return (synth(802, "Redirect"));
}

sub sec_honeypot {
    return (synth(803, "Sexy Honey"));
}

/* call this one for synthetic html */
sub sec_synthtml {
    return (synth(804, "Synthetic"));
}

/* TODO: drop the request..
 *    the plan is to implement VMOD that either
 *    - sends an RST and kills the client connection OR
 *    - kills the client connection silently
 */
sub sec_drop {
     call sec_log;
     vsf.conn_reset();
}

sub sec_throttle {
    if (vsthrottle.is_denied(client.identity, 3, 1s) ||
        vsthrottle.is_denied(client.identity, 10, 30s) ||
        vsthrottle.is_denied(client.identity, 30, 5m)) {
        return (synth(429, "Calm down"));
    }
}

sub sec_magichandler {
    if (!req.http.X-VSF-Response ) {
        ## The default attack response message, can be overridden by rules.
        set req.http.X-VSF-Response = "Naughty, not nice!";
    }
    if (req.http.X-VSF-Response ~ "^honeypot me$") {
        # we have restarted and our request is on the honeypot backend
        # pass the request;
        return (pass);
    }
}
/* You can define how to handle the different severity levels. */
sub sec_handler {
    ## retrieve the rule info
    set req.http.X-VSF-Rule = req.http.X-VSF-Module + "-" +
        req.http.X-VSF-RuleID;
    if (req.http.X-VSF-Rule ~ "^(fooobs)$") {
        # squelch this rule
    } else {
        ## magichandler handles restarts should always be called!
        call sec_magichandler;

        if (req.http.X-VSF-Severity == "1") {
            /* we have only one severity for now: this is the default rule */
            call sec_default_handler;
        } else {
            # fallback attack response when severity is off the charts
            call sec_default_handler;
        }

        # this variable always present, so rule always false
        if (!req.http.X-VSF-Client ) {
            # all functions must be used in vcl, fool compiler by putting
            # them here

            std.log("security.vcl WONTREACH: available sec handlers");
            #  the handlers are defined in main.vcl along with the error codes
            #      handler name  # code # purpose
            call sec_general;    # 800  # debug handler - delivers
                                        # X-VSF-Rule to client
            call sec_reject;     # 801  # 403 reject with message
            call sec_redirect;   # 802  # 302 redirect
            call sec_honeypot;   # 803  # restart request with honeypot
                                        # backend
            call sec_synthtml;   # 804  # synthesize a response
            call sec_drop;       # 805  # drop the request (not implemented)
            call sec_myhandler;  # any  # do your own thing
            call sec_default_handler;   # fallback handler
            call sec_throttle;
            ## note! the passthru handler really does pass thru
            # - you must make sure it is the last thing called
            call sec_passthru;   # n/a  # log client and pass thru to
                                        # default error logic
        }
    }
}

/* vim: set syntax=c tw=76: */
