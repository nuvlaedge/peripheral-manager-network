# peripheral-manager-network


[![Maintenance](https://img.shields.io/badge/Maintained%3F-yes-green.svg?style=for-the-badge)](https://github.com/nuvlaedge/peripheral-manager-network/graphs/commit-activity)
[![GitHub issues](https://img.shields.io/github/issues/nuvlaedge/peripheral-manager-network?style=for-the-badge&logo=github&logoColor=white)](https://GitHub.com/nuvlaedge/peripheral-manager-network/issues/)
[![Docker pulls](https://img.shields.io/docker/pulls/nuvlaedge/peripheral-manager-network?style=for-the-badge&logo=Docker&logoColor=white)](https://cloud.docker.com/u/nuvlaedge/repository/docker/nuvlaedge/peripheral-manager-network)
[![Docker image size](https://img.shields.io/docker/image-size/nuvladev/peripheral-manager-network/master?logo=docker&logoColor=white&style=for-the-badge)](https://cloud.docker.com/u/nuvlaedge/repository/docker/nuvlaedge/peripheral-manager-network)


![CI Build](https://github.com/nuvlaedge/peripheral-manager-network/actions/workflows/main.yml/badge.svg)
![CI Release](https://github.com/nuvlaedge/peripheral-manager-network/actions/workflows/release.yml/badge.svg)


**This repository contains the source code for the NuvlaEdge Peripheral Manager for network devices - this microservice is responsible for the discovery, categorization and management of all [NuvlaEdge](https://sixsq.com/nuvlaedge) network peripherals.**

This microservice is an integral component of the NuvlaEdge Engine.


---

**NOTE:** this microservice is part of a loosely coupled architecture, thus when deployed by itself, it might not provide all of its functionalities. Please refer to https://github.com/nuvlaedge/deployment for a fully functional deployment

---

## Build the NuvlaEdge Peripheral Manager for network devices

This repository is already linked with Travis CI, so with every commit, a new Docker image is released.

There is a [POM file](pom.xml) which is responsible for handling the multi-architecture and stage-specific builds.

**If you're developing and testing locally in your own machine**, simply run `docker build .` or even deploy the microservice via the local [compose files](docker-compose.yml) to have your changes built into a new Docker image, and saved into your local filesystem.

**If you're developing in a non-master branch**, please push your changes to the respective branch, and wait for Travis CI to finish the automated build. You'll find your Docker image in the [nuvladev](https://hub.docker.com/u/nuvladev) organization in Docker hub, names as _nuvladev/peripheral-manager-network:\<branch\>_.

## Deploy the NuvlaEdge Peripheral Manager for network devices

The NuvlaEdge Peripheral Manager for network will only work if a [Nuvla](https://github.com/nuvla/deployment) endpoint is provided and a NuvlaEdge has been added in Nuvla.

Why? Because this microservice has been built to report directly to Nuvla. Every network device will be registered in Nuvla and associated with **an existing** NuvlaEdge.

### Prerequisites

 - *Docker (version 18 or higher)*
 - *Docker Compose (version 1.23.2 or higher)*
 - *Linux*

### Environment variables

|                          	|                                                                                                                                                       	|
|-------------------------	|------------------------------------------------------------------------------------------------------------------------------------------------------	|
|           NUVLAEDGE_UUID 	| (**required**) before starting the microservice, make sure you export the ID of the NuvlaEdge you've created through Nuvla: `export NUVLAEDGE_UUID=<nuvlaedge id from nuvla>` 	|
| NUVLA_ENDPOINT_INSECURE 	| if you're using an insecure Nuvla endpoint, set this to `True`: `export NUVLA_ENDPOINT_INSECURE=True`                                                	|
|          NUVLA_ENDPOINT 	| if you're not using [nuvla.io](https://nuvla.io) then set this to your Nuvla endpoint: `export NUVLA_ENDPOINT=<your endpoint>`                                      	|
| | |

### Launching the NuvlaEdge Peripheral Manager for network devices

Simply run `docker-compose up --build`

### If Nuvla is running on `localhost`

Simply run `docker-compose -f docker-compose.localhost.yml up --build`

## Testing

This microservice is completely automated, meaning that as long as all the proper environment variables have been correctly set and the right dependencies have been met, the respective Docker container will start by itself and automatically start registering peripherals into Nuvla, in real-time.

## Contributing

This is an open-source project, so all community contributions are more than welcome. Please read [CONTRIBUTING.md](CONTRIBUTING.md)

## Copyright

Copyright &copy; 2021, SixSq SA
