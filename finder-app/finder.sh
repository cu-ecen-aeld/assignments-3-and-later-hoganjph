#!/bin/sh

# check that there are two arguments
if [ "$#" -ne 2 ]; then
    echo "Usage: ./finder.sh <search directory> <search string>"
    exit 1
fi

if [ ! -d "$1" ]; then
    echo "The directory does not exist. Exiting"
    exit 1
fi

echo "The number of files are $(ls $1 | wc -l) and the number of matching lines are $(grep -r $2 $1 | wc -l)"
