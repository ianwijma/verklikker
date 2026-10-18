#!/usr/bin/env bash
set -euo pipefail
resize2fs /dev/vda
device=$(ip -o link show | awk -F': ' '/5a:94:ef:e4:0c:ee/ {print $2; exit}')
[ -n "$device" ]
ip link set "$device" up
ip address add 192.168.127.2/24 dev "$device"
ip route add default via 192.168.127.1
ip -6 address add fd00:7665::2/64 dev "$device"
ip -6 route add default via fd00:7665::1
printf '%s\n' 'nameserver 192.168.127.1' > /etc/resolv.conf
exec /usr/local/bin/node /opt/verklikker/dist/apps/guest/main.js
