#!/opt/vfw-web/bin/python
# Eduardo S. Scarpellini <scarpellini@gmail.com>
#                                    Jun 25 2011
#
from bottle import run, route, get, post, request, response, static_file, abort, template, debug
from datetime import datetime
from hashlib import md5
from simplejson import loads, dumps
from redis import Redis
from GeoIP import new, GEOIP_MEMORY_CACHE


debug(True)

db = Redis()


@get("/static/:path#.+#")
def server_static(path):
    return static_file(path, root='/opt/vfw-web/vfw-web/static')


@get("/")
@get("/index")
def main():
    abort(200, "VFW Web!")


@post("/logthreat")
def logthreat():
    """Store VFW log on Redis.
    """

    vfw_log_keys = ["timestamp", "threat", "ruleid", "clientip", "method",\
                    "url", "proto", "ua"]
    vfw_log_in = request.body.readline()
    vfw_log = None

    if not vfw_log_in:
        abort(400, "No log data received")

    try:
        vfw_log = loads(vfw_log_in)
    except Exception, e:
        abort(400, "Invalid log data (JSON expected)")

    for key in vfw_log_keys:
        if not vfw_log.has_key(key):
            abort(400, "No %s specified" % key)

    try:
        vfw_log["clientcountry"] = new(GEOIP_MEMORY_CACHE)\
                                   .country_code_by_addr(vfw_log["clientip"]).upper()
    except Exception, e:
        vfw_log["clientcountry"] = None
        #pass

    try:
        db_key = "log:%s:%s:%s" % (vfw_log["timestamp"],\
                                  vfw_log["ruleid"],\
                                  md5(vfw_log["url"]).hexdigest())

        db.set(db_key, dumps(vfw_log))
    except Exception:
        abort(500, "Error storing log data")


@get("/logs.json")
def jsonlogs():
    """Logs in JSON
    """

    try:
        sorted_keys = sorted(db.keys("log:*"), reverse=True,\
                      key=lambda k: float(k.split(":")[1]) )
    except Exception:
        abort(500, "Database Error")

    sorted_log = []
    for key in sorted_keys:
        ktmp = loads(db.get(key))
        ktmp["datetime"] = datetime.utcfromtimestamp(float(ktmp["timestamp"]))\
                           .strftime("%Y-%m-%d %H:%M:%S")
        sorted_log.append(ktmp)

    response.content_type = "application/json"

    return dumps({"page": 1, "total": len(sorted_log), "data": sorted_log})


@get("/viewlogs")
def viewlogs():
    """View stored logs
    """

    return template("tpls/web_viewlogs")


run(host="0.0.0.0", port=8080)
