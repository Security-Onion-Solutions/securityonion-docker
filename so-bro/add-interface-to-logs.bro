function http_intf_path_func(id: Log::ID, path: string, rec: HTTP::Info): string {
    local peer = get_event_peer()$descr;
    if ( peer in Cluster::nodes && Cluster::nodes[peer]?$interface ) {
        local face = split_string(Cluster::nodes[peer]$interface, /::/);
        return cat("http_", face[1]);
    }

    return "http";
}

event bro_init()
{
    if ( ! reading_live_traffic() )
            return;
    Log::remove_default_filter(HTTP::LOG);
    Log::add_filter(HTTP::LOG, [$name = "http-interfaces",
                                $path_func = http_intf_path_func]);
}
