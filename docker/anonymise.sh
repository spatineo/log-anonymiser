#!/bin/bash

## Usage: ./anonymise.sh inputfile outputfile [additional options]

set -e

VERSION=1.1.1

INPUTFILE_RAW=$1; shift
OUTPUTFILE_RAW=$1; shift

if [ ! -f "$INPUTFILE_RAW" ]; then
    echo $INPUTFILE_RAW: does not exist
    exit 1
fi

if [ -f "$OUTPUTFILE_RAW" ]; then
     echo $OUTPUTFILE_RAW: will not overwrite outputfile
     exit 2
fi

INPUTFILE=$(realpath $INPUTFILE_RAW)

OUTPUTDIR=$(dirname $(realpath -m $OUTPUTFILE_RAW))
OUTPUTFILE=$(basename $(realpath -m $OUTPUTFILE_RAW))

mkdir -p $OUTPUTDIR

docker run \
    --rm \
    --user $(stat -c "%u:%g" $INPUTFILE) \
    --mount type=bind,source=$INPUTFILE,destination=/tmp/inputfile \
    --mount type=bind,readonly=false,source=$OUTPUTDIR,destination=/tmp/outputdir \
    spatineo/log-anonymiser:1.1.1 /tmp/inputfile $OUTPUTFILE $*