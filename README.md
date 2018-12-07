# dockerwall
A packet filter for communications from Docker containers to its default gateway. Configurable by labels.

Run DockerWall container on all hosts you want to limit access of running containers to the Internet, so that even if those containers gets compromised, they will have limited network access to the Internet or to your internal network.

By default all containers are denied access to any host, except those in docker networks that it is directly attached.

Simply add label "dockerwall.outbound=www.yahoo.com" to the container that will be allowed access to www.yahoo.com. DockerWall will configure hosts's IPTables chains/rules to ACCEPT those packets and DROP the others.

DockerWall will automatically update the IPs related to domain names periodically.

Tested with standalone containers, docker-compose and Swarm Clusters.

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

# Swarm Clusters

   * Run DockerWall with "global" placement, so that all managers and workers of the cluster will have an instance of DockerWall, controling access of all containers in the cluster
