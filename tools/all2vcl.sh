#!/bin/sh

set -e
path_to=${1:-crs/*rules}
for i in $path_to/modsecurity_crs_[2345]*
do 
   v=`basename $i`
   v=${v#modsecurity_crs_}
   echo $v
   ./tools/2vcl.pl $i > vcl/breach/${v%.conf}.vcl
done
