# Using portsentry with Docker

Visit the official Portsentry Docker Hub page for detailed and up to date information on how to run portsentry with docker [https://hub.docker.com/r/portsentry/portsentry](https://hub.docker.com/r/portsentry/portsentry).

## Docker compose

In this repository, a template ``docker-compose.yaml`` file exists, it will run portsentry with sensible options.

## Tags

As of right now (when portsentry 2.0 is in beta) it is highly recommended to use the ``:unstable`` tag. This version has been stable for a few months

These are the available tags

| Tag Name | Description |
| -------- | ----------- |
| unstable | Follows the master branch, unreleased versions |
| latest | Follows the latest stable release version |
| stable | Same as latest |
| v1.2 | The old **legacy/unmaintained** version |
