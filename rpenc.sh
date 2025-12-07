#!/bin/bash

random_string() {
    chars=({A..Z} {a..z} {0..9})
    random_string=""
    for i in {1..6}; do
        random_string+=${chars[RANDOM % ${#chars[@]}]}
    done
    echo "$random_string"
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
ARCH=$(uname -m)

case "$OS" in
    "Linux")        EXEC="bin/rpenc-linux-$ARCH" ;;
    "macOS")        EXEC="bin/rpenc-macos-$ARCH" ;;
    "FreeBSD")      EXEC="bin/rpenc-freebsd-$ARCH" ;;   
    "OpenBSD")      EXEC="bin/rpenc-openbsd-$ARCH" ;;   
    "NetBSD")       EXEC="bin/rpenc-netbsd-$ARCH" ;;   
    *)
        echo "Unsupported OS or architecture: $OS"
        echo "If you are on Windows use rpenc.bat"
        exit 1
        ;;
esac

if [ ! -f "$EXEC" ]; then
    echo "There isn't file $EXEC, maybe you can find it in https://github.com/Cinnamon415/rpenc-cli/releases or if it isn't exist you can compile it from source."
    exit 1
fi

if [[ -x "$EXEC" ]]; then
    echo "Running $EXEC..."
    ./"$EXEC" "$@"
else
    echo "Executing failed, trying to run via dynamic loader..."
    
    if [[ -x /lib64/ld-linux-x86-64.so.2 ]]; then
        echo "Using /lib64/ld-linux-x86-64.so.2..."
        /lib64/ld-linux-x86-64.so.2 "$EXEC" "$@" || { 
            echo "Failed to execute with /lib64/ld-linux-x86-64.so.2, trying next method..."; 
        }
    fi

    if [[ -x /lib/ld-linux-x86-64.so.2 ]]; then
        echo "Using /lib/ld-linux-x86-64.so.2..."
        /lib/ld-linux-x86-64.so.2 "$EXEC" "$@" || { 
            echo "Failed to execute with /lib/ld-linux-x86-64.so.2."; 
        }
    else
        echo "No suitable dynamic loader found."
    fi

    echo "Error: Executable '$EXEC' not found or not executable. Copying to /tmp..."
    TEMP_EXEC="/tmp/rpenc-$(random_string)"
    cp "$EXEC" "$TEMP_EXEC"
    chmod +x "$TEMP_EXEC"

    PARENT_DIR="$(dirname "$(realpath "$0")")"
    ENCRYPTED_DIR="$PARENT_DIR/encrypted"

    INPUT_DIR="$PARENT_DIR"
    OUTPUT_DIR="$ENCRYPTED_DIR"
    
    while getopts "i:o:" opt; do
        case $opt in
            i) INPUT_DIR="$OPTARG" ;;
            o) OUTPUT_DIR="$OPTARG" ;;
        esac
    done

    if [[ "$1" == "encrypt" ]]; then
        "$TEMP_EXEC" -i "$INPUT_DIR" -o "$OUTPUT_DIR" "$@" 
    elif [[ "$1" == "decrypt" ]]; then
        "$TEMP_EXEC" -i "$OUTPUT_DIR" -o "$INPUT_DIR" "$@"
    else
        "$TEMP_EXEC" "$@"
    fi
fi
