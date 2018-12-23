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

  * GATEWAY_NETWORKS - Docker networks from which traffic will be filtered by DockerWall. If empty, all "bridge" networks will be discovered and used for filtering. If you use ! in front of a network name, it won't be managed by DockerWall and all traffic will be allowed through this bridge.
  * DEFAULT_OUTBOUND - comma separated list of outbound hosts authorized for all containers by default, so that even if the container doesn't have the "dockerwall.output" label, it will be allowed to access those hosts.

# Prometheus metrics

   * Metrics exposed at http://localhost:50000/metrics
   * Number of packets and bytes dropped/accepted per container etc

# Swarm Clusters

   * You cannot run DockerWall as a Swarm service because Swarm doesn't allow you to run in network_mode host, which is required. Run with plain docker-compose on each manager/worker host.
   * Thou, DockerWall will manage correctly all container instances from Swarm Tasks (we are using it this way!)

# Practical Considerations

   * If you stop Dockerwall containers, no iptables or ipset rules will be changed, so that you can update Dockerwall and no running containers will be affected. If you need to completelly disable Dockerwall DROP/ALLOW effects, stop the container and run ```iptables -F DOCKER-USER```

   * If you don't specify DockerWall gateway networks, all bridge networks will be managed. It means that even the "docker build" task won't have access to the Internet because it uses the "bridge" network in order to have Internet access during build. You may set ENV "GATEWAY_NETWORKS=!bridge" in order to protect all but the "bridge" network, so that regular builds will work.

