#!/bin/bash
# Run this from the root directory. E.g. ./build/build-image.sh
set -e

BUILD_IMAGE_NAME="go-alpine-builder"
OUTPUT_IMAGE_NAME="janeczku/redwall"

ARGS=$@
if [ -z "$ARGS" ]; then
    echo "need version string as argument (e.g. 'build.sh 0.3.0')"
    exit 1
fi

echo "building image" ${OUTPUT_IMAGE_NAME}:${ARGS}

# Build compiler image
docker build -t ${BUILD_IMAGE_NAME} -f build/Dockerfile.build .
# Build output image
docker run --rm ${BUILD_IMAGE_NAME} | docker build -t ${OUTPUT_IMAGE_NAME} -f Dockerfile.run -
# Tag with version number
docker tag -f ${OUTPUT_IMAGE_NAME}:latest ${OUTPUT_IMAGE_NAME}:${ARGS}
# Push
docker push ${OUTPUT_IMAGE_NAME}:latest
docker push ${OUTPUT_IMAGE_NAME}:${ARGS}

echo "Done!"
