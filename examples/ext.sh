#!/bin/sh
#
#	ext.sh <ext.txt
#

PATTERN='\<(file)?name(\*[0-9]+)?=(3D)?.[^\\\/:*?"<>|]*\.(ade|adp|bas|bat|chm|cmd|com|cpl|crt|exe|hlp|hta|inf|ins|isp|js|jse|lnk|mda|mdb|mde|mdz|msc|msi|msp|mst|pcd|pif|reg|scr|sct|shs|shb|url|vb|vbe|vbs|wsc|wsf|wsh)\>'

if grep -i -q -E "$PATTERN"; then
	echo "Windows executable file attachement not allowed" 
	exit 2
fi

exit 0
