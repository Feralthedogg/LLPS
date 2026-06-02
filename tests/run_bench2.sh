#!/bin/bash
set -e
apt-get update && apt-get install -y iperf3
echo "Starting iperf3 server on 25566..."
iperf3 -s -p 25566 -D
echo "Starting LLPS..."
./build/llps -c config.yml > llps_debug.log 2>&1 &
LLPS_PID=$!
sleep 1
echo "Running iperf3 client via LLPS on 25565 (100 Concurrent Connections)..."
timeout 15 iperf3 -c 127.0.0.1 -p 25565 -P 100 -t 5 || true
kill $LLPS_PID 2>/dev/null || true
pkill iperf3 || true
