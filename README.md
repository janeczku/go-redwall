# RedWall - a container-based distributed dynamic firewall with Redis backend

This repository provides the [janeczku/redwall](https://registry.hub.docker.com/u/janeczku/redwall/) image.

-------

[![](https://badge.imagelayers.io/janeczku/redwall:0.4.2.svg)](https://imagelayers.io/?images=janeczku/redwall:latest 'Get your own badge on imagelayers.io')
[![Docker Pulls](https://img.shields.io/docker/pulls/janeczku/redwall.svg?style=flat-square)](https://hub.docker.com/r/janeczku/redwall/)

## About

RedWall (**Red**is Fire**wall**) is slim Alpine Linux based image acting as a firewall agent for managing iptables rules on a single server or whole clusters. The port- or IP-based rules are centrally stored in a Redis database and updates are dynamically applied to all hosts running the RedWall image.

**Filter logic**

In order to co-exist with the firewall rules created by the Docker daemon, RedWall inserts a jump rule at the top of the `INPUT` and `FORWARD` chains. Traffic arriving on the public interface is processed in the `redwall-main` user chain. Traffic not matching any of the port- or IP-based rules is dropped.

## Getting Started

### Prerequisites

1. Setup a Redis instance accessible by the hosts that will run the RedWall Docker image
2. Enable Redis keyspace events notifications by including `notify-keyspace-events Ks` in redis.conf or by typing `CONFIG SET notify-keyspace-events Ks` in redis-cli.
3. Disable any existing firewall daemon on the hosts (e.g. UFW)

### Firewall interface

RedWall is designed to only filter traffic arriving on the specified public interface. This would normally be `eth0`. The public interface can be configured by either passing an environmental variable to the RedWall Docker container or by storing it in the Redis database in the key `firewall:<security-group>:interface`.

Configure the interface name in the database:

	redis-cli SET firewall:<security-group>:interface eth0

Configure the interface name locally for a server:

	docker run --env PUBLIC_IFACE=eth1 (...)


### Port-based rules

Port-based rules are stored in the database as members of the set `firewall:<security-group>:services` formatted as `label:protocol:port`. 

**Example**
Allow public access to a Nginx instance running on port 80/443:

	redis-cli SADD firewall:<security-group>:services http:tcp:80
	redis-cli SADD firewall:<security-group>:services https:tcp:443

### IP-based rules
Traffic matching an IPv4 address or network entry in the `firewall:<security-group>:whitelist` set will be allowed open access to all ports on the server.
Values can be plain IPv4 addresses or networks (with /mask).

**Example**
Allow access to all ports for IP address `208.208.208.208`:

	redis-cli SADD firewall:<security-group>:whitelist 208.208.208.208

**Example**
Allow access to all ports for network `208.208.208.1/24`:

    redis-cli SADD firewall:<security-group>:whitelist 208.208.208.1/24

### Running the RedWall image

    docker run -d --name redwall \
    --cap-add=NET_ADMIN --net=host \
    --env REDIS_HOST=*REPLACE_WITH_REDIS_IP:PORT* \
    --env PUBLIC_IFACE=eth0 \
    --restart on-failure janeczku/redwall

Alternatively, if your version of Docker doesn't support the `--cap-add` switch:

    docker run -d --name redwall \
    --privileged --net=host \
    --env REDIS_HOST=*REPLACE_WITH_REDIS_IP:PORT*
    --env PUBLIC_IFACE=eth0 \
    --restart on-failure janeczku/redwall


## ENV variables
### Required

**REDIS_HOST**  
Default: `REDIS_HOST=`  
The address of the Redis instance as `ip:port`.

**PUBLIC_IFACE**  
Default: `PUBLIC_IFACE=`  
The name of the public interface on the server. This is the interface that will be firewalled.

### Optional

**SECURITY_GROUP**  
Default: `SECURITY_GROUP=default`  
The name of the firewall security group from which rules are applied

**REDIS_PASS**  
Default: `REDIS_PASS=`  
The password for a password-protected Redis instance. Leave empty to disable password-authentication.

**FILTER_DOCKER**  
Default: `FILTER_DOCKER=TRUE`  
Set to `FALSE` to disable filtering docker container network (FORWARD chain)

**ALLOW_SSH**  
Default: `ALLOW_SSH=TRUE`  
Allow public access to SSH (port 22). Set to `FALSE` only if you know what you are doing.

**LIMIT_SSH_ATTACKS**  
Default: `LIMIT_SSH_ATTACKS=FALSE`  
Detect and rate-limit SSH brute-force attacks. Set to `TRUE` to enable.

**REDWALL_DEBUG**  
Default: `REDWALL_DEBUG=FALSE`  
Set to `TRUE` to enable debug log (run `docker logs redwall` to inspect the log)
