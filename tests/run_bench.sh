#!/bin/bash
set -e

apt-get update -yqq && apt-get install -yqq iperf3

# Build release version
rm -rf build && mkdir build && cd build
cmake .. -DCMAKE_BUILD_TYPE=Release
make -j4
cd ..

echo "Starting iperf3 server on 25566..."
iperf3 -s -p 25566 -D

echo "Starting LLPS..."
./build/llps -c config.yml > llps_debug.log 2>&1 &
LLPS_PID=$!
sleep 1


echo "Running iperf3 client via LLPS on 25565 (100 Concurrent Connections)..."
timeout 5 iperf3 -c 127.0.0.1 -p 25565 -P 100 -t 10 || true

echo "Cleaning up..."
kill $LLPS_PID 2>/dev/null || true
echo "=== LLPS PROXY LOG ==="
cat llps_debug.log
echo "======================"
pkill iperf3 || true
