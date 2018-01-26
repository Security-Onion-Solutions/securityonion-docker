# Replace tcpflow to include in sguil interface.

@load base/frameworks/notice
@load base/utils/site
@load base/protocols/dns
@load base/protocols/rdp
@load base/protocols/smtp

# Turn on UDP content delivery.
redef udp_content_deliver_all_resp = T &redef;
redef udp_content_deliver_all_orig = T &redef;

# If HTTP, then output header, reply, entity_data, and request
event http_header(c: connection, is_orig: bool, name: string, value: string)
{
	print fmt("%s: %s", name, value);
}

event http_reply(c: connection, version: string, code: count, reason: string)
{
	print fmt("%s.%d-%s.%d: %s %s", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p, code, reason);
}

event http_entity_data(c: connection, is_orig: bool, length: count, data: string)
{
	print fmt("%s", data);
}

event http_request(c: connection, method: string, original_URI: string, unescaped_URI: string, version: string)
{
	print fmt("%s.%d-%s.%d: %s %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, method, original_URI);
}


# If UDP, output contents and clearly mark SRC and DST sections
event udp_contents(u: connection, is_orig: bool, contents: string)
{
	if (is_orig)
        {
       		print fmt("%s.%d-%s.%d: %s", u$id$orig_h, u$id$orig_p, u$id$resp_h, u$id$resp_p, "Bro UDP output from SRC:");
        }
   		else
        {
       		print fmt("%s.%d-%s.%d: %s", u$id$resp_h, u$id$resp_p, u$id$orig_h, u$id$orig_p, "Bro UDP output from DST:");
        }
	print fmt("%s",contents);
	print "";
}


# If DNS, print the DNS analyzer output and clearly mark it as such
event dns_end(c: connection, msg: dns_msg)
{
       	if ( c?$dns && c$dns$saw_reply && c$dns$saw_query )
	{
       		print fmt("%s.%d-%s.%d: %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, "Bro DNS analyzer output:");
		print "";
       	        print c$dns;
		print "";
        }
}
### Begin SMTP support ###

event smtp_request(c: connection, is_orig: bool, command: string, arg: string)
{
	if(|command| > 0) {
		print fmt("%s.%d-%s.%d:", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
		print fmt("COMMAND: %s", command);
	}
}

event smtp_reply(c: connection, is_orig: bool, code: count, cmd: string, msg: string, cont_resp: bool)
{
        if (|cmd| > 0) {
                print fmt("%s.%d-%s.%d:", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p);
		print fmt("COMMAND: %s", cmd);
        }
}

event mime_one_header(c: connection, h: mime_header_rec)
{
	print h;
}
### End SMTP support ###

### Begin RDP support ###

event rdp_connect_request(c: connection, cookie: string)
{
	print fmt("%s.%d-%s.%d: %s: %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, "Username:", cookie);
}

event rdp_negotiation_response(c: connection, security_protocol: count)
{
	print fmt("%s.%d-%s.%d: %s: %s", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p, "Security Protocol:", c$rdp$security_protocol);
}

event rdp_negotiation_failure(c: connection, failure_code: count)
{
	print fmt("%s.%d-%s.%d: %s: %s", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p, "Result:", c$rdp$result);
}

event rdp_client_core_data(c: connection, data: RDP::ClientCoreData)
{
	print fmt("%s.%d-%s.%d:", c$id$orig_h, c$id$orig_p, c$id$resp_h, c$id$resp_p);
	print fmt("%s: %s", "Keyboard Layout", c$rdp$keyboard_layout);
	print fmt("%s: %s", "Client Build", c$rdp$client_build);
	print fmt("%s: %s", "Client Name", c$rdp$client_name);
	print fmt("%s: %s", "Client Digital Product ID", c$rdp$client_dig_product_id);
	print fmt("%s: %s", "Desktop Width", c$rdp$desktop_width);
	print fmt("%s: %s", "Desktop Height", c$rdp$desktop_height);
}

event rdp_server_security(c: connection, encryption_method: count, encryption_level: count)
{
	print fmt("%s.%d-%s.%d:", c$id$resp_h, c$id$resp_p, c$id$orig_h, c$id$orig_p);
	print fmt("%s: %s", "Encryption Method", c$rdp$encryption_method);
	print fmt("%s: %s", "Encryption Level", c$rdp$encryption_level);
}

### End RDP Support ###

