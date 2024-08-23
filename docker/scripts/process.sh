#!/bin/bash

set -e

INPUT=$1; shift
OUTPUT=$1; shift

java -jar /opt/log-anonymiser/log-anonymiser.jar $INPUT /tmp/outputdir/$OUTPUT $*

