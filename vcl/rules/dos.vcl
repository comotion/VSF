# throttle attempted denial of service attacks
import vsthrottle;

sub sec_throttle {
    if (vsthrottle.is_denied(req.http.X-Actual-IP, 3, 1s) ||
        vsthrottle.is_denied(req.http.X-Actual-IP, 10, 30s) ||
        vsthrottle.is_denied(req.http.X-Actual-IP, 30, 5m)) {
        return (synth(429, "Calm down"));
        # or reset the connection
				#vsf.conn_reset();
    }
}

sub vcl_recv {

    # Extracts first IP from header
    set req.http.X-Actual-IP = regsub(req.http.X-Forwarded-For, "[, ].*$", "");

    # Check requests per second using vsthrottle but exclude js, wp-admin and css
    if ( (!req.http.cookie ~ "wordpress_logged_in") 
         && !(req.url ~ "(eot|ttf|png|js|css|wp-admin|admin-ajax.php|cur|woff(2?)|feedburner)") ) {
        call sec_throttle;
    }
}
