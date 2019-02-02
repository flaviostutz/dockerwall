#!/bin/bash
set -e
set -x

echo "Starting DockerWall..."
dockerwall \
    --loglevel=$LOG_LEVEL \
    --gateway-networks=$GATEWAY_NETWORKS \
    --default-outbound=$DEFAULT_OUTBOUND \
    --dry-run=$DRY_RUN
    

