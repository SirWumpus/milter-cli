#
#	awk -f env.awk env.txt
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

	pattern = "docsis|dpc[0-9]|dsl|client|dhcp|pool[-.]|ppp[-.]|catv|cpe|cust|dial|access|in-addr|arpa|cable|upc-[a-z]|user|bri-|abo\\.|^node[.-]|[0-9]+-[0-9]+-[0-9]+-[0-9]+"
}

NR == nrClientIP {
	client_addr = $0
}

NR == nrClientName {
	client_name = $0
}

NR == nrMAIL && /bounce|noreply|noreturn/ {
	exitStatus = statusDiscard
}

END {
	if (match(client_name, pattern)) {
		print("client " client_name " [" client_addr "] from a dynamic address pool")
		exit(exitStatus);
	}

# Don't do an explicit exit() here, otherwise exit() status' set in 
# an earlier pattern block will be overridden.
#	exit(statusAccept)
}
