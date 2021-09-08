#!/usr/bin/env bash

set -ex

REPO_NAME=alpine
IMAGE_TAG=test
IMAGE_DIGEST=sha256:2582893dec6f12fd499d3a709477f2c0c0c1dfcd28024c93f1f0626b9e3540c8
REPORT_PATH=$(mktemp)
TOP=$(git rev-parse --show-toplevel)
BUILD_DIR=${TOP}/build

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS=linux
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS=darwin
fi

if [[ "$(arch)" == "x86_64" ]]; then
    ARCH=amd64
else
    ARCH=arm
fi

EXECUTABLE=${BUILD_DIR}/aws-ecr-client-${OS}-${ARCH}

REPO_EXISTS=$(aws ecr describe-repositories --query "repositories[*].repositoryName" --output text | grep ${REPO_NAME})

if [ -z "${REPO_EXISTS}" ]; then
    aws ecr create-repository --repository-name ${REPO_NAME} --image-scanning-configuration scanOnPush=true
fi

REPO_URI=$(aws ecr describe-repositories --repository-names alpine --query "repositories[0].repositoryUri" --output text)

docker pull alpine@${IMAGE_DIGEST}
docker tag alpine@${IMAGE_DIGEST} alpine:${IMAGE_TAG}

export AWS_ECR_CLIENT_IGNORE_CVE=CVE-2020-28928
export AWS_ECR_CLIENT_DESTINATION_REPO=${REPO_URI}
export AWS_ECR_CLIENT_IMAGE_TAG=${IMAGE_TAG}
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
${EXECUTABLE}

cat ${REPORT_PATH}

export AWS_ECR_CLIENT_IGNORE_CVE=""
${EXECUTABLE}