/* Security.vcl config VCL file
 * In this file you specify which rulesets to configure.
 *
 */

# Comment out any include line to disable the security module.
# Protocol
include "rules/protocol.vcl";
# Paths/Files extensions
include "rules/paths.vcl";
# Generic attacks
include "rules/generic.vcl";
# SQL Injection
include "rules/sql.vcl";
include "rules/sql.encoded.vcl";
# XSS (Reflected / Stored if post)
include "rules/xss.vcl";
include "rules/xss.encoded.vcl";

include "rules/demo.vcl";
include "rules/php.vcl";
include "rules/cmd.vcl";
include "rules/restricted-file-extensions.vcl";
include "rules/content-encoding.vcl";
include "rules/content-type.vcl";
include "rules/localfiles.vcl";

# you may or may not want the following rulesets:

# DoS connection throttling
#include "rules/dos.vcl";

# check this module, it is rather harsh
#include "rules/request.vcl";

# robot countermeasures (edit robot handler to respond to robots)
#include "rules/robots.vcl";

# cloak the web server and the clients
#include "rules/cloak.vcl";

## User agent checks may be a little too restrictive for your tastes.
#include "rules/user-agent.vcl";

## The breach2vcl tool is not perfect...
# include "breach.vcl";

