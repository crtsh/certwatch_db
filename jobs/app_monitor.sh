#!/bin/bash
pidof $1
result=$?
if [ "${result}" -ne "0" ] ; then
  cd `dirname "$1"`
  screen -d -m -S `basename "$1"` "$1" 2>/dev/null
fi
