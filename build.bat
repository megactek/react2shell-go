@echo off
setlocal

set VERSION=1.1.0
set APP_NAME=scanner
set BUILD_DIR=build

echo Building React2Shell Scanner for Windows...

if not exist %BUILD_DIR% mkdir %BUILD_DIR%

echo Building for Windows (amd64)...
set GOOS=windows
set GOARCH=amd64
go build -ldflags="-s -w" -o %BUILD_DIR%\%APP_NAME%-windows-amd64.exe cmd\scanner\main.go

echo Building for Windows (arm64)...
set GOOS=windows
set GOARCH=arm64
go build -ldflags="-s -w" -o %BUILD_DIR%\%APP_NAME%-windows-arm64.exe cmd\scanner\main.go

echo.
echo Build complete! Binaries are in the %BUILD_DIR% directory:
dir %BUILD_DIR%

