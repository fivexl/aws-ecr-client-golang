#!/usr/bin/env bash

set -ex

create_repo() {
    REPO_EXISTS=$(aws ecr describe-repositories --query "repositories[*].repositoryName" --output text | grep ${1} || true)

    if [ -z "${REPO_EXISTS}" ]; then
        aws ecr create-repository --repository-name ${1} --image-scanning-configuration scanOnPush=true
    fi
}

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

# Prepare image to scan
docker pull alpine@${IMAGE_DIGEST}

# Prepare ECR repo for the test
create_repo ${REPO_NAME}
REPO_URI=$(aws ecr describe-repositories --repository-names ${REPO_NAME} --query "repositories[0].repositoryUri" --output text)

docker tag alpine@${IMAGE_DIGEST} ${REPO_URI}:${IMAGE_TAG}
export AWS_ECR_CLIENT_IGNORE_CVE="CVE-2020-28928 CVE-2021-42374 CVE-2021-42375"
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL="MEDIUM"
export AWS_ECR_CLIENT_DESTINATION_REPO=${REPO_URI}
export AWS_ECR_CLIENT_IMAGE_TAG=${IMAGE_TAG}
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
${EXECUTABLE}

# Check there is a report
cat ${REPORT_PATH}

# Test repo name with slash
create_repo ${REPO_NAME}/test
REPO_URI=$(aws ecr describe-repositories --repository-names ${REPO_NAME}/test --query "repositories[0].repositoryUri" --output text)
docker tag alpine@${IMAGE_DIGEST} ${REPO_URI}:${IMAGE_TAG}

export AWS_ECR_CLIENT_IGNORE_CVE=CVE-2020-28928
export AWS_ECR_CLIENT_DESTINATION_REPO=${REPO_URI}
export AWS_ECR_CLIENT_IMAGE_TAG=${IMAGE_TAG}
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
${EXECUTABLE}

# Test that script fails if we do not ignore CVEs
# since there are CVEs in that image
export AWS_ECR_CLIENT_IGNORE_CVE=""
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL=""
${EXECUTABLE}