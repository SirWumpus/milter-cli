#
#	awk -f ext.awk ext.txt
#
BEGIN {
	### Configure this. Note that if you have multiple pattern rules
	### consider using unique +detail addresses for each redirection
	### rule so that you can identify which rule was triggered.
	spamMailBox = "quarantine@example.com"

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

	# File attachments
	zip_files = "(zip|rar)"
	win_file_chars = "[^\\\\/:*?\"<>|]*"
	win_ext_list = "\\.(ade|adp|bas|bat|chm|cmd|com|cpl|crt|exe|hlp|hta|inf|ins|isp|js|jse|lnk|mda|mdb|mde|mdz|msc|msi|msp|mst|pcd|pif|reg|scr|sct|shs|shb|url|vb|vbe|vbs|wsc|wsf|wsh)"
	content_type_name = "name(\\*[0-9]+)?=(3D)?."
	pattern = content_type_name "" win_file_chars "" win_ext_list
}

NR == 1 {
	messageId = $0
}

#
# No point bouncing a message from a mailing list.
#

/Precedence:.*(list|bulk|junk)/ {
	exitStatus = statusDiscard
}

#
# File attachments
#

$0 ~ pattern {
	match($0, win_file_chars "" win_ext_list)
	print("\"" substr($0, RSTART, RLENGTH) "\" file attachement not allowed")
	
	print(" ")
	print("These Windows executable file extensions are blocked:")
	print(" ")
	print("  ade,  adp,  bas,  bat,  chm,  cmd,  com,  cpl,  crt,  exe,")
	print("  hlp,  hta,  inf,  ins,  isp,  js,   jse,  lnk,  mda,  mdb,")
	print("  mde,  mdz,  msc,  msi,  msp,  mst,  pcd,  pif,  reg,  scr,")
	print("  sct,  shs,  shb,  url,  vb,   vbe,  vbs,  wsc,  wsf,  wsh")
	print(" ")

	exit(exitStatus)
}

$0 ~ (content_type_name "" win_file_chars "" zip_files) {
	print(spamMailBox)
	exit(statusRedirect)
}

#
# Anti-Virus Notices 
#

   /^Subject: *MDaemon Notification -- Attachment Removed/ \
|| /^Subject:.*Virus.*(Alert|Notification|found|IN YOUR MAIL|IN MAIL FROM YOU|detected)/ \
|| /^Subject:.*detected .*(virus|infected)/ \
|| /^Subject:.*InterScan NT Alert/ \
|| /^Subject:.*Symantec Mail Security detected/ \
|| /^Subject:.*Antigen found/ \
|| /^Subject:.*BANNED FILENAME .*IN MAIL FROM YOU/ \
|| /^Subject:.*Suppression du Virus / \
{
	print("anti-virus notices rejected")
	exit(exitStatus)
}
