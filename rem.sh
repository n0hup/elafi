#!/usr/bin/env bash
IF=eth0
HOST=$(ifconfig ${IF} | grep 'inet ' | cut -d ' ' -f 2)
NAME="elafi@${HOST}"
COOKIE="wildwildwest"
printf "NAME='${NAME}'\nCOOKIE='${COOKIE}'\n"
iex --name "${NAME}" --cookie "${COOKIE}"
