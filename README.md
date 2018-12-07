# dockerwall
A packet filter for communications from Docker containers to its default gateway.  Configurable by labels

# Usage

docker.compose.yml
```
version: '3.5'

services:

  dockerwall:
    image: flaviostutz/dockerwall
    cap_add:
      - NET_ADMIN
    network_mode: host
    volumes:
      - /var/run/docker.sock:/var/run/docker.sock

  test:
    image: busybox:1.29
    command: sh -c "ping www.google.com"
    labels:
      - "dockerwall.outbound=www.yahoo.com,www.google.com"
```

* Run ```docker-compose up```

* Observe that ping is working because "www.google.com" was added to "dockerwall.outbound" label

* Remove "www.google.com" from "dockerwall.outbound" label on docker-compose.yml

* Run ```docker-compose up``` and observe that pings will stop working (hopefully!)

# ENV configurations
  * GATEWAY_NETWORKS - Docker networks from which traffic will be filtered by DockerWall. If empty, all "bridge" networks will be discovered and used for filtering.

# Prometheus metrics

   * Metrics exposed at http://localhost:8000/metrics
