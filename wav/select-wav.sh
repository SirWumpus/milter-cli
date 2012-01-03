#!/bin/sh
#

PATH=/bin:/usr/bin

if test -n "$PATH_INFO"; then
	FILE=`dirname $SCRIPT_FILENAME`"$PATH_INFO"
        EPOCH_SECONDS=`date +'%s'`
        LINES=`wc -l $FILE |tr -s ' '|cut -d' ' -f 2`
        LINE_NUMBER=`expr $EPOCH_SECONDS % $LINES + 1`
elif test $# = 1 ; then
        FILE=$1
        EPOCH_SECONDS=`date +'%s'`
        LINES=`wc -l $FILE |tr -s ' '|cut -d' ' -f 2`
        LINE_NUMBER=`expr $EPOCH_SECONDS % $LINES + 1`
elif test $# = 2 ; then
        FILE=$2
        LINE_NUMBER=$1
else
        echo "usage: select-line.sh [number] file"
        exit 2
fi

echo
sed -n -e "${LINE_NUMBER}{
s#^\(.*\)	\(.*\)#\&laquo;<a class=\"large\" href=\"wav/\1\">\2</a>\&raquo;<br/>#
p
}" $FILE

exit 0
