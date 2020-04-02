#!/bin/bash
screen -S `basename "$1"` -Q select . >/dev/null
#pidof $1 >/dev/null
result=$?
if [ "${result}" -ne "0" ] ; then
  cd `dirname "$1"`
  screen -d -m -S `basename "$1"` "$1" 2>/dev/null
fi
