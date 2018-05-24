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
FABRIC_IMAGES=(fabric-peer fabric-ca fabric-ccenv fabric-javaenv  fabric-tools)

for image in ${FABRIC_IMAGES[@]}; do
  echo "taging ${DOCKER_NS}/$image:${ARCH}-${VERSION}"
  docker tag ${DOCKER_NS}/$image:${ARCH}-${VERSION} ${DOCKER_NS}/$image:latest
done

echo "taging ${DOCKER_NS}/fabric-couchdb:${COUCHDB}"
docker tag ${DOCKER_NS}/fabric-couchdb:${COUCHDB} ${DOCKER_NS}/fabric-couchdb:latest

echo "taging ${DOCKER_NS}/fabric-baseos:${BASE_DOCKER_TAG}"
docker tag ${DOCKER_NS}/fabric-baseos:${BASE_DOCKER_TAG} ${DOCKER_NS}/fabric-baseos:latest