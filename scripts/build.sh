#!/usr/bin/env bash

set -ex

VERSION=${1}
[ -z "${VERSION}" ] && VERSION=$(git describe --tags)

TOP="$(git rev-parse --show-toplevel)"
REPO_NAME="$(basename ${TOP})"
BUILD_DIR="${TOP}/build"
RELEASE_DIR="${TOP}/release/${REPO_NAME}/${VERSION}"
BINARY_NAME="aws-ecr-client"

rm -rf "${BUILD_DIR}" "${RELEASE_DIR}"

mkdir -p "${BUILD_DIR}" "${RELEASE_DIR}"

TARGET_GOOSES=("linux" "darwin" "windows")
TARGET_GOARCHES=("amd64" "arm")

# Build static binaries so we can run them on alpine 
export CGO_ENABLED=0

for OS in "${TARGET_GOOSES[@]}"
do
    for ARCH in "${TARGET_GOARCHES[@]}"
    do
        if [ "${ARCH}" == "arm" ] && [ "${OS}" != "linux" ]; then
            continue
        fi
        echo "Building for ${OS} and arch ${ARCH}"
        export GOOS="${OS}"
        export GOARCH="${ARCH}"
        go build -a -o "build/${BINARY_NAME}-${GOOS}-${GOARCH}" -ldflags "-s -w -X main.VERSION=${VERSION}"
        cp "build/${BINARY_NAME}-${GOOS}-${GOARCH}" "build/${BINARY_NAME}"
        zip -j "${RELEASE_DIR}/${BINARY_NAME}_${VERSION}_${OS}_${ARCH}.zip" "build/${BINARY_NAME}"
        rm -rf "build/${BINARY_NAME}"
    done
done

cd "${RELEASE_DIR}"
for FILE in *.zip
do
    sha256sum "${FILE}" > "${FILE%.zip}_sha256"
done
