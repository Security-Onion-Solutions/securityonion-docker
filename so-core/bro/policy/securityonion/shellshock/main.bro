
@load base/frameworks/notice
@load base/protocols/http
@load base/utils/time
@load base/utils/addrs

@load-sigs ./shellshock-http
@load-sigs ./file-mimetypes

module ShellShock;

export {
	redef enum Notice::Type += {
		## Indicates a high likelihood of successful shellshock exploitation.
		Exploit,
		## Indicates that a host was detected as scanning for shellshock vulnerable hosts.
		Scanner,
	};

	redef enum HTTP::Tags += {
		HIT
	};

	## The number of apparent attacks a host must send for it to be 
	## detected as ShellShock::Scanner.
	const scan_threshold = 10 &redef;

	## The period over which scanner detection is performed.
	const scan_detection_period = 10min &redef;

	## This contains a list of MIME types that would typically be
	## seen as droppers after the exploitation of ShellShock.
	const post_exploit_file_types: set[string] = {
		"application/x-executable", ##< elf executables (and some others)
		"application/x-dosexec",    ##< windows executables in case someone is exploiting cygwin
		"text/x-php",
		"text/x-perl",
		"text/x-shellscript",
	} &redef;

	## The pattern for matching shellshock attacks.  This is 
	## also defined separately in the .sig file.
	const matcher = /.*(\(|%28)(\)|%29)( |%20)(\{|%7B)/ &redef;
}

redef Signatures::actions += {
	["shellshock-http"] = Signatures::SIG_IGNORE
};

# Please be careful with this.
redef record SumStats::Observation += {
	shellshock_victim: addr &optional;
};

event bro_init()
	{
	local r1 = SumStats::Reducer($stream="shellshock.possible_http_victim", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=1);

	local r2 = SumStats::Reducer($stream="shellshock.possible_smtp_victim", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=1);

	local r3 = SumStats::Reducer($stream="shellshock.possible_dhcp_victim", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=1);

	local r4 = SumStats::Reducer($stream="shellshock.possible_post_exploit_file", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=1);

	local r5 = SumStats::Reducer($stream="shellshock.possible_post_exploit_ping", 
	                             $apply=set(SumStats::LAST),
	                             $num_last_elements=1);

	SumStats::create([$name="look-for-shellshock",
	                  $epoch=5mins,
	                  $reducers=set(r1, r2, r3, r4, r5),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
	                  	{
	                  	local exploit_file = result["shellshock.possible_post_exploit_file"];
	                  	local exploit_ping = result["shellshock.possible_post_exploit_ping"];
	                  	return exploit_ping$num + exploit_file$num + 0.0;
	                  	},
	                  $threshold = 1.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
	                  	{
	                  	local http_attacks = result["shellshock.possible_http_victim"];
	                  	local smtp_attacks = result["shellshock.possible_smtp_victim"];
	                  	local dhcp_attacks = result["shellshock.possible_dhcp_victim"];
	                  	local total_attacks = http_attacks$num + smtp_attacks$num + dhcp_attacks$num;
	                  	
	                  	local exploit_file = result["shellshock.possible_post_exploit_file"];
	                  	local exploit_ping = result["shellshock.possible_post_exploit_ping"];
	                  	if ( total_attacks > 0 )
	                  		{
	                  		local attack_msg = "Attack over";
	                  		local exploit_msg = "";
	                  		local detect_interval: interval;

	                  		if ( http_attacks$num > 0 )
	                  			{
	                  			attack_msg = fmt("%s HTTP", attack_msg);
	                  			detect_interval = exploit_file$begin-http_attacks$end;
	                  			}
	                  		else if ( smtp_attacks$num > 0 )
	                  			{
	                  			attack_msg = fmt("%s SMTP", attack_msg);
	                  			detect_interval = exploit_file$begin-smtp_attacks$end;
	                  			}
	                  		else if ( dhcp_attacks$num > 0 )
	                  			{
	                  			attack_msg = fmt("%s DHCP", attack_msg);
	                  			detect_interval = exploit_file$begin-dhcp_attacks$end;
	                  			}

	                  		if ( exploit_file$num > 0 )
	                  			{
	                  			exploit_msg = fmt("requested a potential dropper within %.2f seconds of an attack", detect_interval);
	                  			}
	                  		if ( exploit_ping$num > 0 )
	                  			{
	                  			if ( exploit_msg != "" )
	                  				exploit_msg += " and ";

	                  			local ping_dst = SumStats::get_last(exploit_ping)[0]$str;
	                  			exploit_msg = fmt("%ssent a ping to %s within %.2f seconds of an attack.", exploit_msg, ping_dst, detect_interval);
	                  			}

	                  		NOTICE([$note=Exploit,
	                  		        $src=key$host,
	                  		        $msg=fmt("High likelihood of successful CVE-2014-6271 exploitation against %s.  %s and %s", key$host, attack_msg, exploit_msg),
	                  		        $sub=fmt("%s and %s", attack_msg, exploit_msg),
	                  		        $identifier=cat(key$host)]);
	                  		}
	                  	}]);


	local r6 = SumStats::Reducer($stream="shellshock.possible_http_attacker", 
	                             $apply=set(SumStats::SAMPLE),
	                             $num_samples=5);

	local r7 = SumStats::Reducer($stream="shellshock.possible_smtp_attacker", 
	                             $apply=set(SumStats::SAMPLE),
	                             $num_samples=5);

	local r8 = SumStats::Reducer($stream="shellshock.possible_dhcp_attacker", 
	                             $apply=set(SumStats::SAMPLE),
	                             $num_samples=5);

	SumStats::create([$name="shellshock-find-scanners",
	                  $epoch=scan_detection_period,
	                  $reducers=set(r6, r7, r8),
	                  $threshold_val(key: SumStats::Key, result: SumStats::Result): double =
	                  	{
	                  	local http_attacks = result["shellshock.possible_http_attacker"];
	                  	local smtp_attacks = result["shellshock.possible_smtp_attacker"];
	                  	local dhcp_attacks = result["shellshock.possible_dhcp_attacker"];
	                  	return http_attacks$num + smtp_attacks$num + dhcp_attacks$num + 0.0;
	                  	},
	                  $threshold = scan_threshold + 0.0,
	                  $threshold_crossed(key: SumStats::Key, result: SumStats::Result) = 
	                  	{
	                  	local http_attacks = result["shellshock.possible_http_attacker"];
	                  	local smtp_attacks = result["shellshock.possible_smtp_attacker"];
	                  	local dhcp_attacks = result["shellshock.possible_dhcp_attacker"];
	                  	local total_attacks = http_attacks$num + smtp_attacks$num + dhcp_attacks$num;

	                  	local payload = "";
	                  	local period = 0secs;
	                  	local victim_addrs = "";
	                  	local i = 0;
	                  	if ( http_attacks$num > 0 )
	                  		{
	                  		period = http_attacks$end - http_attacks$begin;
	                  		for ( i in http_attacks$samples )
	                  			{
	                  			payload = http_attacks$samples[i]$str;
	                  			victim_addrs = fmt("%s%s%s", victim_addrs, |victim_addrs|>0 ? ", " : "", http_attacks$samples[i]$shellshock_victim);
	                  			}
	                  		}
	                  	else if ( smtp_attacks$num > 0 )
	                  		{
	                  		period = smtp_attacks$end - smtp_attacks$begin;
	                  		for ( i in smtp_attacks$samples )
	                  			{
	                  			payload = dhcp_attacks$samples[i]$str;
	                  			victim_addrs = fmt("%s%s%s", victim_addrs, |victim_addrs|>0 ? ", " : "", smtp_attacks$samples[i]$shellshock_victim);
	                  			}
	                  		}
	                  	else if ( dhcp_attacks$num > 0 )
	                  		{
	                  		period = dhcp_attacks$end - dhcp_attacks$begin;
	                  		for ( i in dhcp_attacks$samples )
	                  			{
	                  			payload = dhcp_attacks$samples[i]$str;
	                  			victim_addrs = fmt("%s%s%s", victim_addrs, |victim_addrs|>0 ? ", " : "", dhcp_attacks$samples[i]$shellshock_victim);
	                  			}
	                  		}

	                  	if ( |payload| > 100 )
	                  		{
	                  		payload = payload[0:99] + "<too long, trimmed by Bro>";
	                  		}

	                  	NOTICE([$note=Scanner,
	                  	        $src=key$host,
	                  	        $msg=fmt("%s sent at least %d CVE-2014-6271 exploit attempts in %s.", key$host, total_attacks, duration_to_mins_secs(period)),
	                  	        $sub=fmt("Used payload: \"%s\" against sample victim hosts: %s", payload, victim_addrs),
	                  	        $identifier=cat(key$host)]);
	                  	}]);
	}


function ShellShock::http_header_sig_match(state: signature_state, data: string): bool
	{
	local c = state$conn;
	if ( c?$http )
		add c$http$tags[ShellShock::HIT];

	SumStats::observe("shellshock.possible_http_victim", [$host=c$id$resp_h], [$str=data]);
	SumStats::observe("shellshock.possible_http_attacker", [$host=c$id$orig_h], [$str=data, $shellshock_victim=c$id$resp_h]);

	return F;
	}

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
	{
	if ( command == /[mM][aA][iI][lL]/ && /^[fF][rR][oO][mM]:/ in arg &&
	     matcher in arg )
		{
		SumStats::observe("shellshock.possible_smtp_victim", [$host=c$id$resp_h], [$str=arg]);
		SumStats::observe("shellshock.possible_smtp_attacker", [$host=c$id$orig_h], [$str=arg, $shellshock_victim=c$id$resp_h]);
		}
	}


event dhcp_ack(c: connection, msg: dhcp_msg, mask: addr, router: dhcp_router_list, lease: interval, serv_addr: addr, host_name: string)
	{
	if ( matcher in host_name )
		{
		SumStats::observe("shellshock.possible_dhcp_victim", [$host=c$id$resp_h], [$str=host_name]);
		SumStats::observe("shellshock.possible_dhcp_attacker", [$host=c$id$orig_h], [$str=host_name, $shellshock_victim=c$id$resp_h]);
		}
	}

function observe_post_exploit_file(c: connection, f: fa_file, mime_type: string)
	{
	if ( f$info$is_orig && f$source == "HTTP" )
		return;

	if ( mime_type in post_exploit_file_types )
		{
		local host = f$is_orig ? c$id$resp_h : c$id$orig_h;
		SumStats::observe("shellshock.possible_post_exploit_file", [$host=host], [$str=mime_type]);
		}
	}

# Deal with version compatibility issues
@if ( /2\.(3\-[23])/ in bro_version() )
event file_mime_type(f: fa_file, mime_type: string)
	{
	for ( cid in f$conns )
		{
		local c = f$conns[cid];
		observe_post_exploit_file(c, f, mime_type);
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( f?$mime_type )
		{
		observe_post_exploit_file(c, f, f$mime_type);
		}
	}
@endif

# Deal with version compatibility issues
@if ( /2\.(3\-[78]|4)/ in bro_version() )
event file_sniff(f: fa_file, meta: fa_metadata)
	{
	if ( meta?$mime_type )
		{
		for ( cid in f$conns )
			{
			local c = f$conns[cid];
			observe_post_exploit_file(c, f, meta$mime_type);
			}
		}
	}

event file_over_new_connection(f: fa_file, c: connection, is_orig: bool)
	{
	if ( f$info?$mime_type )
		{
		observe_post_exploit_file(c, f, f$info$mime_type);
		}
	}
@endif

event icmp_echo_request(c: connection, icmp: icmp_conn, id: count, seq: count, payload: string)
	{
	SumStats::observe("shellshock.possible_post_exploit_ping", [$host=c$id$orig_h], [$str=cat(c$id$resp_h)]);
	}

