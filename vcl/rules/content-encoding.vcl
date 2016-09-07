
# For now
sub sec_contentencoding_sev1 {
    set req.http.X-VSF-Severity = "1";
    set req.http.X-VSF-Module = "contentencoding";
    call sec_handler;
}

sub vcl_recv {

    # Security.vcl does not support content encodings
    if (req.http.Content-Encoding ~ "!^Identity$") {
        set req.http.X-VSF-RuleName = "Inbound compressed content";
        set req.http.X-VSF-RuleID   = "1";
        set req.http.X-VSF-RuleInfo = "Blocks inbound compressed content";
        call sec_contentencoding_sev1;
    }
}
