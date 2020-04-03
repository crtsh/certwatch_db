#!/bin/bash
result=0
while [ $result -eq 0 ]; do
  app_pid=`pidof $1`
  result=$?
  if [ $result -eq 0 ]; then
    kill -s INT $app_pid
    sleep 1
  fi
done

result=0
for i in 1 2 3 4 5; do
  screen -S `basename "$1"` -Q select . >/dev/null
  result=$?
  if [ $result -ne 0 ] ; then
    cd `dirname "$1"`
    screen -d -m -S `basename "$1"` "$1" 2>/dev/null
    break
  elif [ $i -gt 4 ] ; then
    echo "$1: screen -Q did not work as expected"
  fi
  sleep 1
done
