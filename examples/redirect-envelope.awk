#
#	awk -f redirect-envelope.awk input-file
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

        nrClientIP      = 1
        nrClientName    = 2
        nrHELO          = 3
        nrMAIL          = 4
        nrMessageId     = 5
        nrFirstRCPT     = 6
}

NR == nrMAIL && /hans@gmx.net/ {
	from_annoying_sender = 1;
}

NR <= nrFirstRCPT && /user@our.domain/ {
	if (from_annoying_sender) {
		print("abuse@our.domain");
		exit(statusRedirect);
	}
}
