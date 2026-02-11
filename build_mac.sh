#!/bin/bash

echo "Detected macOS system build request."
SPEC_FILE="ApkDetecter.spec"

if [ ! -f "$SPEC_FILE" ]; then
    echo "Error: $SPEC_FILE not found."
    exit 1
fi

echo "Starting build with $SPEC_FILE..."

# Clean previous build/dist
if [ -d "build" ]; then
    echo "Cleaning build directory..."
    rm -rf build
fi

if [ -d "dist" ]; then
    echo "Cleaning dist directory..."
    rm -rf dist
fi

# Run PyInstaller
echo "Running PyInstaller..."
pyinstaller "$SPEC_FILE" --clean --noconfirm

if [ $? -eq 0 ]; then
    echo ""
    echo "Build successful!"
    echo "App bundle is in dist/ApkDetecter.app"
else
    echo ""
    echo "Build failed."
    exit 1
fi
