BEGIN {
        "date +'%j%H%M%S'" | getline messageId
        tmp = "/tmp/" messageId ".clam"
}

NR == 1 {
        if (match($0, "^Return-Path:") == 0 && match($0, "^From ") == 0) {
                messageId = $0
                tmp = "/tmp/" messageId ".eml"
                next
        }
}

{
	print $0 >tmp
}
