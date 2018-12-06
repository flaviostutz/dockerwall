#!/bin/bash
set -e
set -x

echo "Starting DockerWall..."
dockerwall \
    --loglevel=$LOG_LEVEL \
    --gateway-networks=$GATEWAY_NETWORKS

