module LogFilter;

event zeek_init()
{
    Log::remove_default_filter(Files::LOG);

    Log::add_filter(Files::LOG, [$name = "files-noise",
                                    $pred(rec: Files::Info) = {
                                        for (tx_host in rec$tx_hosts) {
                                            if ((rec?$mime_type) && ((rec$mime_type == "application/pkix-cert") || (rec$mime_type == "application/x-x509-ca-cert") || (rec$mime_type == "application/x-x509-user-cert") ))
                                                return F;
                                            return T;
                                            }
                                        return T;
                                    }
                                ]);
}
