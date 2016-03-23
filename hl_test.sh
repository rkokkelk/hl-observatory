#!/bin/bash
LOGFILE="/var/log/hl-observatory.setup"
EXECPATH=$(PWD)
FMTDATE=$(date +%d-%m-%y' '%H:%M:%S)
./get_geoinfo.sh
python3 observatory.py -n test_$(cat hostinfo) -t targets.lst
if [ $(cat $EXECPATH/results/test*.json | python3 -m json.tool | wc -l) -gt 10 ];then echo "$FMTDATE - Initial Test Successful!" >> $LOGFILE && $EXECPATH/hl_exec.sh;else echo "$FMTDATE - Initial Test Failed" >> $LOGFILE;fi

