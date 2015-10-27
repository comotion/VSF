sub vcl_recv {
  	set req.http.X-Actual-IP = regsub(req.http.X-Forwarded-For, "[, ].*$", "");
 
	# Use throttle mod to check requests per second, excludes logged in users, js, wp-admin and css
    if(throttle.is_allowed("ip:" + req.http.X-Actual-IP, "6req/s") > 0s  && (!req.http.cookie ~ "wordpress_logged_in") && !(req.url ~ "(eot|ttf|png|js|css|wp-admin|admin-ajax.php|cur|woff(2?)|feedburner)") ) {
        call sec_throttle;
    }
}
