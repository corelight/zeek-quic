
@load Corelight/GQUIC

event gquic_packet(c: connection, is_orig: bool, hdr: GQUIC::PublicHeader)
	{
	print "gquic_packet", c$id, is_orig, hdr;
	}

event gquic_client_version(c: connection, version: count)
	{
	print "gquic_client_version", c$id, version;
	}

event gquic_version_negotiation(c: connection, is_orig: bool,
                                versions: index_vec)
	{
	print "gquic_version_negotiation", c$id, is_orig, versions;
	}

event gquic_reset(c: connection, is_orig: bool)
	{
	print "gquic reset", c$id, is_orig;
	}
