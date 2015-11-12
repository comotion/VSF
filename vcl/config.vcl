/* Security.vcl config VCL file
 * In this file you specify which rulesets to configure.
 *
 */

# Comment out any include line to disable the security module.
# Protocol
include "security/rules/protocol.vcl";
# Paths/Files extensions
include "security/rules/paths.vcl";
# Generic attacks
include "security/rules/generic.vcl";
# SQL Injection
include "security/rules/sql.vcl";
include "security/rules/sql.encoded.vcl";
# XSS (Reflected / Stored if post)
include "security/rules/xss.vcl";
include "security/rules/xss.encoded.vcl";

include "security/rules/demo.vcl";
include "security/rules/php.vcl";
include "security/rules/cmd.vcl";
include "security/rules/restricted-file-extensions.vcl";
include "security/rules/content-encoding.vcl";
include "security/rules/content-type.vcl";
include "security/rules/localfiles.vcl";

# you may or may not want the following rulesets:

# DoS connection throttling
#include "security/rules/dos.vcl";

# check this module, it is rather harsh
#include "security/rules/request.vcl";

# robot countermeasures (edit robot handler to respond to robots)
#include "security/rules/robots.vcl";

# cloak the web server and the clients
#include "security/rules/cloak.vcl";

## User agent checks may be a little too restrictive for your tastes.
#include "security/rules/user-agent.vcl";

## The breach2vcl tool is not perfect...
# include "security/breach.vcl";

