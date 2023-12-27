#!/bin/bash

# check that there are two arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: ./writer.sh <write file> <write string>"
    exit 1
fi

# Create parent directories if they don't exist
mkdir -p "$(dirname "$1")"
echo $2 > $1
