signature shellshock-http-header {
	ip-proto == tcp
	http-request-header /.*(\(|%28)(\)|%29)( |%20)(\{|%7B)/

	eval ShellShock::http_header_sig_match
}