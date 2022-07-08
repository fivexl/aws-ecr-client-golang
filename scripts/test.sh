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
MACHINE_ARCH=$(arch)
BUILD_DIR=${TOP}/build

if [[ "$OSTYPE" == "linux-gnu"* ]]; then
    OS=linux
elif [[ "$OSTYPE" == "darwin"* ]]; then
    OS=darwin
fi

if [[ "$MACHINE_ARCH" == "x86_64" || "$MACHINE_ARCH" == "i386" ]]; then
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

# Test scratch image
export SCRATCH_IMAGE_TAG=${IMAGE_TAG}-scratch
docker pull resin/scratch
docker tag resin/scratch ${REPO_URI}:${SCRATCH_IMAGE_TAG}
export AWS_ECR_CLIENT_IGNORE_CVE="ECR_ERROR_UNSUPPORTED_IMAGE"
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL=""
export AWS_ECR_CLIENT_DESTINATION_REPO=${REPO_URI}
export AWS_ECR_CLIENT_IMAGE_TAG=${SCRATCH_IMAGE_TAG}
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
${EXECUTABLE}

docker tag alpine@${IMAGE_DIGEST} ${REPO_URI}:${IMAGE_TAG}
export AWS_ECR_CLIENT_IGNORE_CVE="CVE-2020-28928 CVE-2021-42374 CVE-2021-42375 CVE-2022-28391 ALPINE-13661"
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

export AWS_ECR_CLIENT_DESTINATION_REPO=${REPO_URI}
export AWS_ECR_CLIENT_IMAGE_TAG=${IMAGE_TAG}
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
${EXECUTABLE}

# Test that script fails if we do not ignore CVEs
# since there are CVEs in that image
export AWS_ECR_CLIENT_IGNORE_CVE="CVE-2021-42386"
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL="LOW"
set +e
${EXECUTABLE}
if [ "$?" == 0 ]; then
    echo "this test should have failed. there are CVEs in the image"
fi
set -e

# Test that script fails if there are repeated CVE ids or levels
# We used to have a bug (fixed in 0.5.1) that caused to scan result to be set
# to passed when user repeared the same levels twice and we didn't account for that
# resulting in number of ignored CVEs being higher than total number of CVEs reported :facepalm:
export AWS_ECR_CLIENT_IGNORE_CVE="CVE-2020-28928 CVE-2020-28928 CVE-2020-28928 CVE-2020-28928 CVE-2020-28928 CVE-2020-28928 CVE-2020-28928"
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL="MEDIUM MEDIUM MEDIUM"
set +e
${EXECUTABLE}
if [ "$?" == 0 ]; then
    echo "this test should have failed. there are CVEs in the image"
fi
set -e

echo "All good"
