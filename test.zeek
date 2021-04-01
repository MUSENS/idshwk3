global relaTable: table[addr] of set[string];
event http_all_headers (c: connection, is_orig: bool, hlist: mime_header_list)
	{
	local sourIp: addr = c$id$orig_h;
	local ua: string;
	local uaSet: bool = F;
	for(first, second in hlist)
		{
		if(second$name == "USER-AGENT")
			{
			ua = second$value;
			uaSet = T;		
			}
		}
	if(uaSet)
		{
		if(sourIp in relaTable)
			{
			add relaTable[sourIp][to_lower(ua)];
			}
		else
			{
			relaTable[sourIp] = set(to_lower(ua));
			}
		}
	}
event zeek_done()
	{
	for(sourIp, ua in relaTable)
		{
		if(|ua| >= 0)
			{
			print fmt("%s is a proxy", sourIp);
			}
		}
	}
