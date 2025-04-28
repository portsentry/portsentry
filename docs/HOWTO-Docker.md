# Using Portsentry with Docker

## Versions

As of right now (when portsentry 2.0 is in beta) it is highly recommended to use the ``:unstable`` tag. This version has been stable for a few months

| Tag Name | Description |
| -------- | ----------- |
| unstable | Follows the master branch, unreleased version |
| latest | Follows the latest stable release version |
| v1.2 | The old **legacy/unmaintained** version |

## Quickstart
```
docker run -d --network=host --name portsentry portsentry/portsentry:unstable
```

### Mounting important directories and files

There are **three** important files/directories you might want to consider mounting:

* The configuration file
* The ignore file
* The log directory

The configuration file should be mounted to `/etc/portsentry/portsentry.conf` and the ignore file to `/etc/portsentry/portsentry.ignore`. The log directory should be mounted to `/var/log`.

You can download the example config and ignore file with extensive documentation here:

https://github.com/portsentry/portsentry/blob/master/examples/portsentry.conf

https://github.com/portsentry/portsentry/blob/master/examples/portsentry.ignore

Here is a complete example of how to run Portsentry with a custom configruation and ignore file and the log directory mounted:


```
docker run -d --mount type=bind,src=./portsentry.ignore,dst=/etc/portsentry/portsentry.ignore \
--mount type=bind,src=./portsentry.conf,dst=/etc/portsentry/portsentry.conf \
--mount type=bind,src=./logs,dst=/var/log \
--network=host --name portsentry portsentry/portsentry:unstable
```

## Using Docker Compose

An example docker-compose file can be found here:

https://github.com/portsentry/portsentry/blob/master/docker/docker-compose.yaml

Here is an example of how to run Portsentry with a custom configuration and ignore file and the log directory mounted using Docker Compose:

```
services:
  portsentry:
    container_name: portsentry
    image: portsentry/portsentry:unstable
    restart: unless-stopped
    network_mode: host
    volumes:
      - type: bind
        source: ./portsentry.conf
        target: /etc/portsentry/portsentry.conf
        read_only: true
      - type: bind
        source: ./portsentry.ignore
        target: /etc/portsentry/portsentry.ignore
        read_only: true
      - type: bind
        source: ./logs
        target: /var/log
```

## Fail2ban Integration

It is highly recommended to use Portsentry with fail2ban if you want to block ip addresses. Fail2ban is able to block ip addresses using a wide variety of methods and will enforce state between system reboots and service restarts.

Get the fail2ban integration files here: https://github.com/portsentry/portsentry/tree/master/fail2ban

## Visit the Portsentry project at

Website: https://portsentry.xyz/

Github: https://github.com/portsentry/portsentry
