
# For now
sub sec_contenttype_sev1 {
        set req.http.X-VSF-Severity = "1";
        call sec_handler;
}

sub vcl_recv {
        set req.http.X-VSF-Module =  "contenttype";

        # Checks for which content-types we accept in GET and HEAD request: application/x-www-form-urlencoded, multipart/form-data request and text/xml
        if(( req.request == "GET" || req.request == "HEAD" )
        # Content-type: application/x-www-form-urlencoded; charset=utf-8
#          && req.http.Content-Type ~ "(?:^(?:application\/x-www-form-urlencoded(?:;(?:\s?charset\s?=\s?[\w\d\-]{1,18})?)??$|multipart/form-data;)|text/xml)" ) {
          && req.http.Content-Type ~ "application\/x-www-form-urlencoded;(\s?charset\s?=\s?[\w\d\-]{1,18})?|multipart/form-data;|text/xml" ) {
                set req.http.X-VSF-RuleName = "Request content type restricted";
                set req.http.X-VSF-RuleID   = "1";
                set req.http.X-VSF-RuleInfo = "Checks for accepted content-types";
                call sec_contenttype_sev1;
        }
}
