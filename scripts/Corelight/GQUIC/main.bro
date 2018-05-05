
module GQUIC;

export {

}

const ports = { 80/udp, 443/udp };
redef likely_server_ports += { ports };

# probably best to rely on signature match
#event bro_init() &priority=5
#	{
#	Analyzer::register_for_ports(Analyzer::ANALYZER_GQUIC, ports);
#	}
