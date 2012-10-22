
# For now
sub sec_restrictedfileextentions_sev1 {
        set req.http.X-VSF-Severity = "1";
        call sec_handler;
}

sub vcl_recv {
        set req.http.X-VSF-Module =  "restrictedfileextentions";

        # List of file extensions to not allow (blacklist) 
#        if ( req.url ~ "\.(?:c(?:o(?:nf(?:ig)?|m)|s(?:proj|r)?|dx|er|fg|md)|p(?:rinter|ass|db|ol|wd)|v(?:b(?:proj|s)?|sdisco)|a(?:s(?:ax?|cx)|xd)|d(?:bf?|at|ll|os)|i(?:d[acq]|n[ci])|ba(?:[kt]|ckup)|res(?:ources|x)|s(?:h?tm|ql|ys)|l(?:icx|nk|og)|\w{0,5}~|webinfo|ht[rw]|xs[dx]|key|mdb|old)$" ) {
        if ( req.url ~ "\.(c(o(nf(ig)?|m)|s(proj|r)?|dx|er|fg|md)|p(rinter|ass|db|ol|wd)|v(b(proj|s)?|sdisco)|a(s(ax?|cx)|xd)|d(bf?|at|ll|os)|i(d[acq]|n[ci])|ba([kt]|ckup)|res(ources|x)|s(h?tm|ql|ys)|l(icx|nk|og)|\w{0,5}~|webinfo|ht[rw]|xs[dx]|key|mdb|old)$" ) {
                set req.http.X-VSF-RuleName = "Restricted file extensions";
                set req.http.X-VSF-RuleID   = "1";
                set req.http.X-VSF-RuleInfo = "Checks for file extensions that are not allowed";
                call sec_restrictedfileextentions_sev1;
        }
}
