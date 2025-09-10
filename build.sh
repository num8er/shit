#!/usr/bin/env bash

set -e

echo "Building Shit Applications..."
echo "============================="

mkdir -p bin

echo "Downloading dependencies..."
go mod download

echo ""
echo "Building shit-shell (reverse shell client)..."
go build -o bin/shit-shell cmd/shit-shell/main.go
echo "✓ shit-shell built successfully"

echo ""
echo "Building shit-man (server)..."
go build -o bin/shit-man cmd/shit-man/main.go
echo "✓ shit-man built successfully"

echo ""
echo "Building shit (CLI tool)..."
go build -o bin/shit cmd/shit/main.go
echo "✓ shit built successfully"

echo ""
echo "Build complete! Binaries are in the 'bin' directory:"
ls -la bin/

echo ""
echo "To install, run: ./install.sh"