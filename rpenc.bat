@echo off
setlocal enabledelayedexpansion

set ARCH=
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set ARCH=amd64
) else if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set ARCH=arm64
) else if "%PROCESSOR_ARCHITECTURE%"=="x86" (
    set ARCH=x86
) else (
    echo Error: Unsupported architecture: %PROCESSOR_ARCHITECTURE%
    exit /b 1
)

set EXEC=bin\rpenc-windows-%ARCH%.exe

if not exist "%EXEC%" (
    echo Error: Executable '%EXEC%' not found.
    echo Please make sure you have downloaded the correct binary for your architecture.
    echo Architecture detected: %ARCH%
    exit /b 1
)

echo Running %EXEC% with arguments: %*
"%EXEC%" %*

if %errorlevel% neq 0 (
    echo Error: Executable exited with code %errorlevel%
    exit /b %errorlevel%
)

endlocal
