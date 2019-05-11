#!/bin/bash

OUTF=${1%.md}.pdf

CMD="pandoc $1 --pdf-engine=xelatex --variable urlcolor=blue --number-sections --table-of-contents -o $OUTF"

if ! [ -f $1 ]; then

    echo usage: $0 markdown_file
    exit 1

fi

if ! [ -f $OUTF ]; then
    
    $CMD

fi

evince $OUTF &

while inotifywait -e close_write $1; do

    $CMD

done

