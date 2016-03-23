#!/bin/bash
EXECPATH=$(pwd)

$EXECPATH/get_geoinfo.sh
python3 observatory.py -n $(cat $EXECPATH/hostinfo) -t alexa_*.list && echo "COMPLETED Successfuly!"
