#!/bin/bash

# rpenc.sh — portable launcher for rpenc-cli
# Handles FAT32/exFAT/NTFS filesystems where +x permission bit is absent

SCRIPT_DIR="$(cd "$(dirname "$(realpath "$0")")" && pwd)"

random_string() {
    local chars=({A..Z} {a..z} {0..9})
    local result=""
    for i in {1..6}; do
        result+=${chars[RANDOM % ${#chars[@]}]}
    done
    echo "$result"
}

detect_os() {
    case "$(uname -s)" in
        Linux*)     echo "Linux" ;;
        Darwin*)    echo "macOS" ;;
        FreeBSD*)   echo "FreeBSD" ;;
        OpenBSD*)   echo "OpenBSD" ;;
        NetBSD*)    echo "NetBSD" ;;
        *)          echo "Unknown" ;;
    esac
}

OS=$(detect_os)
RAW_ARCH=$(uname -m)

# Normalize architecture names
case "$RAW_ARCH" in
    i386|i486|i586|i686) ARCH="i586" ;;
    x86_64|amd64)        ARCH="x86_64" ;;
    aarch64|arm64)       ARCH="aarch64" ;;
    *)                   ARCH="$RAW_ARCH" ;;
esac

# Build list of candidate binary names in priority order:
# 1. Dynamic (gnu) — faster, requires system glibc
# 2. Static (musl) — universal fallback, works everywhere
# 3. Plain name — for custom/single builds
case "$OS" in
    "Linux")
        CANDIDATES=(
            "bin/rpenc-linux-${ARCH}-gnu"
            "bin/rpenc-linux-${ARCH}-musl"
            "bin/rpenc-linux-${ARCH}"
        ) ;;
    "macOS")
        CANDIDATES=(
            "bin/rpenc-macos-${ARCH}"
        ) ;;
    "FreeBSD")
        CANDIDATES=(
            "bin/rpenc-freebsd-${ARCH}"
        ) ;;
    "OpenBSD")
        CANDIDATES=(
            "bin/rpenc-openbsd-${ARCH}"
        ) ;;
    "NetBSD")
        CANDIDATES=(
            "bin/rpenc-netbsd-${ARCH}"
        ) ;;
    *)
        echo "Unsupported OS or architecture: $OS"
        echo "If you are on Windows use rpenc.bat"
        exit 1
        ;;
esac

# Find first available binary
EXEC_FULL=""
for candidate in "${CANDIDATES[@]}"; do
    if [ -f "$SCRIPT_DIR/$candidate" ]; then
        EXEC_FULL="$SCRIPT_DIR/$candidate"
        break
    fi
done

if [ -z "$EXEC_FULL" ]; then
    echo "No binary found for $OS $ARCH. Searched for:"
    for candidate in "${CANDIDATES[@]}"; do
        echo "  - $SCRIPT_DIR/$candidate"
    done
    echo ""
    echo "Download from https://github.com/Cinnamon415/rpenc-cli/releases or compile from source."
    exit 1
fi

# =============================================
# Method 1: Direct execution (filesystem supports +x)
# =============================================
if [[ -x "$EXEC_FULL" ]]; then
    echo "Running $EXEC_FULL..."
    "$EXEC_FULL" "$@"
    exit $?
fi

echo "File is not executable (likely FAT32/exFAT/NTFS filesystem)."

# =============================================
# Method 2: ld-linux dynamic loader
# Pass --real-exe so rpenc knows its real location
# =============================================
for LD in /lib64/ld-linux-x86-64.so.2 /lib/ld-linux-x86-64.so.2; do
    if [[ -x "$LD" ]]; then
        echo "Using $LD..."
        "$LD" "$EXEC_FULL" --real-exe "$EXEC_FULL" "$@"
        exit $?
    fi
done

# =============================================
# Method 3: Copy to /tmp and set +x
# Pass --real-exe so rpenc knows its real location
# =============================================
echo "No suitable dynamic loader found. Copying to /tmp and setting +x..."

TEMP_EXEC="/tmp/rpenc-$(random_string)"
cp "$EXEC_FULL" "$TEMP_EXEC"
chmod +x "$TEMP_EXEC"

cleanup() {
    rm -f "$TEMP_EXEC"
}
trap cleanup EXIT

"$TEMP_EXEC" --real-exe "$EXEC_FULL" "$@"
exit $?
