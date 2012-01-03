#
#	awk -f env2.awk env.txt
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

NR == nrClientIP {
	client_addr = $0
}

NR == nrClientName {
	client_name = $0

	# Did sendmail resolve the client_addr? */
	if (match(client_name, /\[[0-9]+\.[0-9]+\.[0-9]+\.[0-9]+\]/) != 0)
		;

	# Find the 2nd and top level domains.
	else if (match(client_name, /\.[-0-9a-z]+\.[-0-9a-z]+$/) > 0) {
		subdomain = substr(client_name, 1, RSTART-1)

		if (split(client_addr, octets, ".") == 4) {
			# Look for IPv4 octets in the client name.
			for (i in octets) {
				if (match(subdomain, "[^0-9]*" octets[i] "[^0-9]*"))
					count++
			}

			if (2 <= count) {
				print("[DYNDNS]")
				print("client " client_name " [" client_addr "] from a dynamic address pool")
				exit(statusTag);
			}
		}
	}
}

NR == nrMAIL && /bounce|noreply|noreturn/ {
	exitStatus = statusDiscard
}

NR == nrMessageId {
	messageId = $0
}

END {
# Don't do an explicit exit() here, otherwise exit() status' set in
# an earlier pattern block will be overridden.
#	exit(statusAccept)
}
