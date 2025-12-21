#!/bin/sh

DEFAULT_TARGET="127.0.0.1"

if [ -z "$1" ]; then
    TARGET="$DEFAULT_TARGET"
    echo "[i] No IP provided — defaulting to $TARGET"
else
    TARGET="$1"
fi

PORTS="
21:FTP
22:SSH
23:Telnet
25:SMTP
53:DNS
80:HTTP
110:POP3
111:RPCBind
135:MSRPC
139:SMB
143:IMAP
443:HTTPS
445:SMB
993:IMAPS
1433:SQL Server
2375:Docker API
2377:Docker Swarm
3000:Web Dev / Node
3306:MySQL
3389:RDP
5000:Docker Registry / Web
6443:Kubernetes API
7946:Docker Overlay Network
8080:HTTP-Alt
8443:HTTPS-Alt
9090:Prometheus / Web
27017:MongoDB
"

echo "Fast scanning $TARGET..."
echo "---------------------------"

echo "$PORTS" | while IFS=: read PORT SERVICE; do
(
    timeout 1 sh -c "echo > /dev/tcp/$TARGET/$PORT" 2>/dev/null \
        && echo "[+] Port $PORT OPEN ($SERVICE)"
) &
done

wait
echo "Scan complete."

