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

#
# No point bouncing a message from a mailing list.
#

NR == 1 {
	messageId = $0
}

/Precedence:.*(list|bulk|junk)/ {
	exitStatus = statusDiscard
}

#
# Scam spam
#

   /^Subject:.*CONGRATULATION/ \
|| /^Subject:.*YOU WON/ \
|| /^Subject:.*(WINNER|WINNING)/ \
|| /^Subject:.*LOTT?O/ \
|| /^Subject:.*FROM (MR|MS|DR)/ \
|| /^Subject:.*(PayPal|eBay).*account/ \
|| /^Return-Path: <security\@ebay\.com>/ \
|| /^From:.*eBay Security Department/ \
|| /^From:.*security@eBay.com/ \
|| /^Subject:.*AWARD (NOTIFICATION|NOTICE)/ \
|| /^(From|Sender):.*Winning *Notification/ \
|| /^(From|Sender):.*lott?o/ \
|| /SWEEPSTAKES|LOTTO/ \
|| /ATTN:.* NOTIFICATION/ \
|| /^Subject:.*eBay Deals/ \
|| /(North|East|West|South) Africa|nigeria/ \
|| /R.PUBLIC OF (B.NIN|TOGO)|Abuja|Libia|LIBERIAN|SIERRA LEONE|Zimbabwe/ \
|| /BUSINESS PROPOSAL|DEAR FRIEND|BUSINESS PARTNERSHIP/ \
|| /(CONFIDENTIAL|INVESTMENT|URGENT|request|SEEKING) .*(ASSISTANCE|BUSINESS|PROPOSAL)/ \
|| /US dollars|dollars US|United States? Dollar|the sum of/ \
|| /([0-9]+) MILLION|HUNDRED THOUSAND/ \
|| /PLEASE HELP|IMMEDIATE RESPONSE|ATTENTION: PLEASE/ \
|| /http:\/\/ectar.aero\/archives\/2003_12_01_archive.html/ \
{
	print("[SCAM]")
	if (debug) print($0)
	exit(statusTag)
}

#
# Regular spam
#

   /^Subject: A(D|[^a-zA-Z0-9]D[^a-zA-Z0-9])V[^a-zA-Z0-9]?/ \
|| /^Subject: Market watch news flash/ \
|| /AS SEEN ON (USA )?(NATIONAL TV|NBC|CBS|ABC|FOX|BBC|ITV|CBC|CTV|City TV|Sky|Oprah|20\/20|60 Minutes)/ \
|| /This is an advertisement/ \
|| /order (NOW|today)/ \
|| /(free trial|SPECIAL|EXCLUSIVE|one time) OFFER/ \
|| /^Subject: BMN PRESS RELEASE/ \
|| /Your application was processed and approved./ \
|| /day money back guarantee/ \
|| /Viagra|v.[a@]gr[a@]|Valium|Diazepam|X[a@]n[a@]x|V\/a\/lium|Cia[l!|]is|citrate|Tadalafil/ \
|| /opt-?(in|out)|Direct Marketing/ \
|| /Viaggra|Vallium|Diazzepam|Ciallis|Phentermiine|ph4rm|Prescr[i1]pt[i1][o0]n/ \
|| /transaction|refinance|Pre-?Approved/ \
|| /Get Pills|Real buy|Best buy|Buy meds|savings on meds|buy Pharmaceuticals|meds online|save on meds/ \
|| /Pharmacy|supply meds|pain relief|cigarette|smokes|drugs|lozenge|medication/ \
|| /erectile|libido|orgasms|climaxes|aphrodisiac/ \
|| /spacer.gif|pixel.gif/ \
|| /rolex|come on in!/ \
{
	print("[SPAM]")
	if (debug) print($0)
	exit(statusTag)
}
