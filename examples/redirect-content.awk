#
#	awk -f redirect-content.awk input-file
#
BEGIN {
	# Hope this is gawk.
	IGNORECASE = 1

	statusAccept	= 0
	statusTempfail	= 1
	statusReject	= 2
	statusDiscard 	= 3
	statusTag	= 4
	statusCopy	= 5
	statusRedirect	= 6

	exitStatus = statusReject
}

NR == 1 {
	messageId = $0
	next
}

/^From:.*hans@gmx.net/ {
	from_annoying_sender = 1;
}

#
/^\(To|Cc\):.*<user@our.domain>/ {
	if (from_annoying_sender) {
		print("abuse@our.domain")
		exit(statusRedirect)
	}
}
