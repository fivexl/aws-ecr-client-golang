#!/usr/bin/env bash

set -ex

create_repo() {
    REPO_EXISTS=$(aws ecr describe-repositories --query "repositories[*].repositoryName" --output text | grep ${1} || true)

    if [ -z "${REPO_EXISTS}" ]; then
        aws ecr create-repository --repository-name ${1} --image-scanning-configuration scanOnPush=true
    fi
}

REPO_NAME=python-test
IMAGE_TAG=test
# python:3.13 based on Debian - has many known CVEs (HIGH, MEDIUM, UNDEFINED)
IMAGE_REF=python:3.13
IMAGE_DIGEST=sha256:498320f325ad70645e99ff676347987ca9117728784b8273fb6d25cc735ad9c0
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
docker pull ${IMAGE_REF}@${IMAGE_DIGEST}

# Prepare ECR repo for the test
create_repo ${REPO_NAME}
REPO_URI=$(aws ecr describe-repositories --repository-names ${REPO_NAME} --query "repositories[0].repositoryUri" --output text)

# Test scratch image
echo "==> TEST: Scratch image (built from scratch with minimal layer)"
export SCRATCH_IMAGE_TAG=${IMAGE_TAG}-scratch
# resin/scratch uses deprecated Docker image format v1, build a minimal scratch image instead
# The image needs at least 1 layer to be pushable to ECR, but should still be unscannable
SCRATCH_TMPDIR=$(mktemp -d)
printf 'FROM scratch\nCOPY Dockerfile /scratch\n' > ${SCRATCH_TMPDIR}/Dockerfile
docker build -t local-scratch ${SCRATCH_TMPDIR}
rm -rf ${SCRATCH_TMPDIR}
docker tag local-scratch ${REPO_URI}:${SCRATCH_IMAGE_TAG}
export AWS_ECR_CLIENT_IMAGES=${REPO_URI}:${SCRATCH_IMAGE_TAG}
export AWS_ECR_CLIENT_IGNORE_CVE="ECR_ERROR_UNSUPPORTED_IMAGE"
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL=""
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
${EXECUTABLE}

echo "==> TEST: python:3.13, ${IMAGE_REF}@${IMAGE_DIGEST}"
docker tag ${IMAGE_REF}@${IMAGE_DIGEST} ${REPO_URI}:${IMAGE_TAG}
export AWS_ECR_CLIENT_IMAGES=${REPO_URI}:${IMAGE_TAG}
# Ignore all severity levels so the scan passes
export AWS_ECR_CLIENT_IGNORE_CVE=""
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL="HIGH MEDIUM UNDEFINED"
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
${EXECUTABLE}

# Check there is a report
cat ${REPORT_PATH}

# Test repo name with slash
echo "==> TEST: python:3.13, ${IMAGE_REF}@${IMAGE_DIGEST}, with repo having slash"
create_repo ${REPO_NAME}/test
REPO_URI=$(aws ecr describe-repositories --repository-names ${REPO_NAME}/test --query "repositories[0].repositoryUri" --output text)
docker tag ${IMAGE_REF}@${IMAGE_DIGEST} ${REPO_URI}:${IMAGE_TAG}

export AWS_ECR_CLIENT_IMAGES=${REPO_URI}:${IMAGE_TAG}
export AWS_ECR_CLIENT_IGNORE_CVE=""
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL="HIGH MEDIUM UNDEFINED"
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
${EXECUTABLE}

# Test that script fails if we do not ignore CVEs
# since there are CVEs in that image
echo "==> TEST: python:3.13, without sufficient ignores - expected to fail"
REPO_URI=$(aws ecr describe-repositories --repository-names ${REPO_NAME} --query "repositories[0].repositoryUri" --output text)
export AWS_ECR_CLIENT_IMAGES=${REPO_URI}:${IMAGE_TAG}
export AWS_ECR_CLIENT_IGNORE_CVE="CVE-2024-58015"
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL=""
export AWS_ECR_CLIENT_JUNIT_REPORT_PATH=${REPORT_PATH}
set +e
${EXECUTABLE}
if [ "$?" == 0 ]; then
    echo "this test should have failed. there are CVEs in the image"
    exit 1
fi
set -e

# Test that script fails if there are repeated CVE ids or levels
# We used to have a bug (fixed in 0.5.1) that caused to scan result to be set
# to passed when user repeared the same levels twice and we didn't account for that
# resulting in number of ignored CVEs being higher than total number of CVEs reported :facepalm:
echo "==> TEST: python:3.13, with duplicated CVE and levels - expected to fail"
export AWS_ECR_CLIENT_IGNORE_CVE="CVE-2024-58015 CVE-2024-58015 CVE-2024-58015 CVE-2024-58015 CVE-2024-58015 CVE-2024-58015 CVE-2024-58015"
export AWS_ECR_CLIENT_IGNORE_CVE_LEVEL="MEDIUM MEDIUM MEDIUM"
set +e
${EXECUTABLE}
if [ "$?" == 0 ]; then
    echo "this test should have failed. there are CVEs in the image"
    exit 1
fi
set -e

echo "All good"
