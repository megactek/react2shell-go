#!/bin/bash

set -e

VERSION="1.1.0"
APP_NAME="scanner"
BUILD_DIR="build"

echo "Building React2Shell Scanner for multiple platforms..."

# Create build directory
mkdir -p $BUILD_DIR

# Build for Linux (amd64)
echo "Building for Linux (amd64)..."
GOOS=linux GOARCH=amd64 go build -ldflags="-s -w" -o $BUILD_DIR/${APP_NAME}-linux-amd64 ./cmd/scanner

# Build for Linux (arm64)
echo "Building for Linux (arm64)..."
GOOS=linux GOARCH=arm64 go build -ldflags="-s -w" -o $BUILD_DIR/${APP_NAME}-linux-arm64 ./cmd/scanner

# Build for macOS (amd64)
echo "Building for macOS (amd64)..."
GOOS=darwin GOARCH=amd64 go build -ldflags="-s -w" -o $BUILD_DIR/${APP_NAME}-darwin-amd64 ./cmd/scanner

# Build for macOS (arm64 - Apple Silicon)
echo "Building for macOS (arm64)..."
GOOS=darwin GOARCH=arm64 go build -ldflags="-s -w" -o $BUILD_DIR/${APP_NAME}-darwin-arm64 ./cmd/scanner

# Build for Windows (amd64)
echo "Building for Windows (amd64)..."
GOOS=windows GOARCH=amd64 go build -ldflags="-s -w" -o $BUILD_DIR/${APP_NAME}-windows-amd64.exe ./cmd/scanner

# Build for Windows (arm64)
echo "Building for Windows (arm64)..."
GOOS=windows GOARCH=arm64 go build -ldflags="-s -w" -o $BUILD_DIR/${APP_NAME}-windows-arm64.exe ./cmd/scanner

echo ""
echo "Build complete! Binaries are in the $BUILD_DIR directory:"
ls -lh $BUILD_DIR/

