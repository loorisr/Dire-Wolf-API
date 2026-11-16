#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

BINARY_NAME="direwolf_api"
BUILD_DIR="build"

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Define targets: OS/ARCH[/GOARM]
TARGETS=(
    "linux/amd64"
    "linux/386"
    "linux/arm64"
    "linux/arm/7"
    "windows/amd64"
    "windows/386"
)

echo "Starting build process for Dire Wolf API..."

for TARGET in "${TARGETS[@]}"; do
    IFS='/' read -r OS ARCH ARM <<< "$TARGET"

    SUFFIX="$ARCH"
    if [ -n "$ARM" ]; then
        SUFFIX="armv${ARM}"
    fi

    OUTPUT="$BUILD_DIR/${BINARY_NAME}_${OS}_${SUFFIX}"
    if [ "$OS" == "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi

    echo "Building for $OS ($SUFFIX)..."
    CGO_ENABLED=0 GOOS=$OS GOARCH=$ARCH GOARM=$ARM \
        go build -trimpath -ldflags="-s -w" -o "$OUTPUT" .
done

echo "Build complete. Binaries are located in the '$BUILD_DIR' directory."
