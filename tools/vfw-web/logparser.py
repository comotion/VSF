#!/opt/vfw-web/bin/python
# Eduardo S. Scarpellini <scarpellini@gmail.com>
#                                    Jun 24 2011
#
from sys import stdin
from urllib2 import Request, urlopen
from re import compile
from simplejson import dumps


# CONFIG
# VFW logthreat URL
VFWWEBLOG = "http://localhost:8080/logthreat"
# VFW log regexp
# <VFW> 1311037137.661951 [SSI Injection/ruleid:generic.ssi-2]: 201.81.211.173 - POST http://ec2-50-19-46-43.compute-1.amazonaws.com/politica/1237583227176.html HTTP/1.1 - metis
VFWREGEX = compile(r'<VFW> ([0-9\.]+) \[([a-zA-Z0-9_\- ]+)/ruleid:([a-zA-Z0-9_\-\. ]+)\]: ([0-9\.]+) - ([A-Z]+) (http\S+) (HTTP/[01]\.[0-9]) - (.*)$')

for line in stdin:
    vfw_log_json = None
    re_match = VFWREGEX.search(line)

    if re_match:
        try:
            vfw_log_json = dumps({
                    "timestamp": re_match.group(1),
                    "threat": re_match.group(2),
                    "ruleid": re_match.group(3),
                    "clientip": re_match.group(4),
                    "method": re_match.group(5),
                    "url": re_match.group(6),
                    "proto": re_match.group(7),
                    "ua": re_match.group(8),
            })

            res = urlopen(Request(VFWWEBLOG, vfw_log_json, {"Content-Type": "application/json"}))
            print "Sent (%s): %s\n\n" % (VFWWEBLOG, vfw_log_json)
        except Exception:
            continue
