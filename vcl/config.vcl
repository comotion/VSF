/* Security.vcl config VCL file
 * In this file you specify which rulesets to configure.
 *
 */

# Comment out any include line to disable the security module.
# Protocol
include "/etc/varnish/security/rules/protocol.vcl";
# Paths/Files extensions
include "/etc/varnish/security/rules/paths.vcl";
# Generic attacks
include "/etc/varnish/security/rules/generic.vcl";
# SQL Injection
include "/etc/varnish/security/rules/sql.vcl";
include "/etc/varnish/security/rules/sql.encoded.vcl";
# XSS (Reflected / Stored if post)
include "/etc/varnish/security/rules/xss.vcl";
include "/etc/varnish/security/rules/xss.encoded.vcl";

include "/etc/varnish/security/rules/demo.vcl";
include "/etc/varnish/security/rules/php.vcl";
include "/etc/varnish/security/rules/cmd.vcl";
include "/etc/varnish/security/rules/restricted-file-extensions.vcl";
include "/etc/varnish/security/rules/content-encoding.vcl";
include "/etc/varnish/security/rules/content-type.vcl";
include "/etc/varnish/security/rules/localfiles.vcl";

# check this module, it is rather harsh
#include "/etc/varnish/security/rules/request.vcl";

# you may or may not want these
#include "/etc/varnish/security/rules/robots.vcl";
#include "/etc/varnish/security/rules/cloak.vcl";

## User agent checks may be a little too restrictive for your tastes.
#include "/etc/varnish/security/rules/user-agent.vcl";

## The breach2vcl tool is not perfect...
# include "/etc/varnish/security/breach.vcl";

