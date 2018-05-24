#!/bin/bash -eu
# Copyright London Stock Exchange Group All Rights Reserved.
#
# SPDX-License-Identifier: Apache-2.0
#
# This script pulls docker images from the Dockerhub hyperledger repositories

# set the default Docker namespace and tag
DOCKER_NS=hyperledger
ARCH=x86_64
VERSION=1.1.0
BASE_DOCKER_TAG=x86_64-0.4.6
KAFKA=x86_64-0.4.7
COUCHDB=x86_64-0.4.6
ZOOKEEPER=x86_64-0.4.7
# set of Hyperledger Fabric images
FABRIC_IMAGES=(fabric-peer fabric-orderer fabric-ca fabric-ccenv fabric-javaenv  fabric-tools)

for image in ${FABRIC_IMAGES[@]}; do
  echo "Pulling ${DOCKER_NS}/$image:${ARCH}-${VERSION}"
  docker pull ${DOCKER_NS}/$image:${ARCH}-${VERSION}
done

echo "Pulling ${DOCKER_NS}/fabric-zookeeper:${ZOOKEEPER}"
docker pull ${DOCKER_NS}/fabric-zookeeper:${ZOOKEEPER}

echo "Pulling ${DOCKER_NS}/fabric-couchdb:${COUCHDB}"
docker pull ${DOCKER_NS}/fabric-couchdb:${COUCHDB}

echo "Pulling ${DOCKER_NS}/fabric-kafka:${KAFKA}"
docker pull ${DOCKER_NS}/fabric-kafka:${KAFKA}

echo "Pulling ${DOCKER_NS}/fabric-baseos:${BASE_DOCKER_TAG}"
docker pull ${DOCKER_NS}/fabric-baseos:${BASE_DOCKER_TAG}