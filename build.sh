#!/bin/bash

# Exit immediately if a command exits with a non-zero status.
set -e

BINARY_NAME="direwolf_api"
BUILD_DIR="build"

# Create build directory if it doesn't exist
mkdir -p "$BUILD_DIR"

# Define targets: OS/ARCH
TARGETS=(
    "linux/amd64"
    "linux/386"
    "windows/amd64"
    "windows/386"
)

echo "Starting build process for Dire Wolf API..."

for TARGET in "${TARGETS[@]}"; do
    OS=$(echo "$TARGET" | cut -d'/' -f1)
    ARCH=$(echo "$TARGET" | cut -d'/' -f2)
    
    OUTPUT="$BUILD_DIR/${BINARY_NAME}_${OS}_${ARCH}"
    if [ "$OS" == "windows" ]; then
        OUTPUT="${OUTPUT}.exe"
    fi

    echo "Building for $OS ($ARCH)..."
    GOOS=$OS GOARCH=$ARCH go build -o "$OUTPUT" .
done

echo "Build complete. Binaries are located in the '$BUILD_DIR' directory."