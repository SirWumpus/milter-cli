#
#	awk -f tags.awk [file...]
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
}

/Precedence:.*(list|bulk|junk)/ {
	exitStatus = statusDiscard
}

#
# Tracking token
#

/[[<#({:](Key|Id):[0-9]+[]#>)}:]/ {
	print("message contains tracking token")
	exit(exitStatus)
}

#
# Inline content such as IFRAME (supicious) and STYLE tags (spammy like behaviour)
#

/<iframe/ {
	hasIframeTag++
}

/src *=(3D)? *"cid:/ {
	hasInlineContent++
}

/<style/ {
	hasStyleTag++
}

END {
	if (hasInlineContent && hasIframeTag) {
		print("message content rejected")
		exit(exitStatus)
	}
	
	if (hasInlineContent && hasStyleTag) {
		print("[ADV]")
		exit(statusTag)
	}	
}