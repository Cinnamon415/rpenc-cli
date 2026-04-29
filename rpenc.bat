@echo off
setlocal enabledelayedexpansion

set "SCRIPT_DIR=%~dp0"

set ARCH=
if "%PROCESSOR_ARCHITECTURE%"=="AMD64" (
    set ARCH=x86_64
) else if "%PROCESSOR_ARCHITECTURE%"=="ARM64" (
    set ARCH=aarch64
) else if "%PROCESSOR_ARCHITECTURE%"=="x86" (
    set ARCH=i686
) else (
    echo Error: Unsupported architecture: %PROCESSOR_ARCHITECTURE%
    exit /b 1
)

REM Try binaries in priority order:
REM 1. msvc (fastest, requires MSVC runtime)
REM 2. gnu (MinGW, self-contained)
REM 3. gnullvm (LLVM-based, needs libunwind.dll in bin/)
REM 4. plain name (custom/single builds)
set "EXEC="

for %%B in (
    "%SCRIPT_DIR%bin\rpenc-windows-%ARCH%-msvc.exe"
    "%SCRIPT_DIR%bin\rpenc-windows-%ARCH%-gnu.exe"
    "%SCRIPT_DIR%bin\rpenc-windows-%ARCH%-gnullvm.exe"
    "%SCRIPT_DIR%bin\rpenc-windows-%ARCH%.exe"
) do (
    if exist %%B if not defined EXEC set "EXEC=%%~B"
)

if not defined EXEC (
    echo Error: No binary found for Windows %ARCH%.
    echo Searched in %SCRIPT_DIR%bin\ for:
    echo   - rpenc-windows-%ARCH%-msvc.exe
    echo   - rpenc-windows-%ARCH%-gnu.exe
    echo   - rpenc-windows-%ARCH%-gnullvm.exe
    echo   - rpenc-windows-%ARCH%.exe
    echo.
    echo Download from https://github.com/Cinnamon415/rpenc-cli/releases or compile from source.
    exit /b 1
)

REM If gnullvm binary was selected, ensure libunwind.dll is in place.
REM DLLs are stored as libunwind-{arch}.dll to support multiple architectures
REM in one bin/ folder, but Windows requires the exact name "libunwind.dll".
echo %EXEC% | findstr /i "gnullvm" >nul 2>&1
if %errorlevel% equ 0 (
    if exist "%SCRIPT_DIR%bin\libunwind-%ARCH%.dll" (
        REM Copy arch-specific DLL to the name Windows expects
        copy /y "%SCRIPT_DIR%bin\libunwind-%ARCH%.dll" "%SCRIPT_DIR%bin\libunwind.dll" >nul 2>&1
    )
    if not exist "%SCRIPT_DIR%bin\libunwind.dll" (
        echo Error: gnullvm binary requires libunwind.dll in %SCRIPT_DIR%bin\
        echo Place the DLL as "libunwind.dll" or "libunwind-%ARCH%.dll" (auto-renamed^).
        echo Without it you will get error code -1073741515 (STATUS_DLL_NOT_FOUND^).
        exit /b 1
    )
)

echo Running %EXEC% with arguments: %*
"%EXEC%" %*

if %errorlevel% neq 0 (
    echo Error: Executable exited with code %errorlevel%
    exit /b %errorlevel%
)

endlocal
