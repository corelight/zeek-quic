#ifndef ANALYZER_PROTOCOL_GQUIC_GQUIC_H
#define ANALYZER_PROTOCOL_GQUIC_GQUIC_H

#include "zeek/zeek-config.h"

#include "zeek/analyzer/protocol/udp/UDP.h"
#include "zeek/analyzer/protocol/pia/PIA.h"

namespace binpac  {
   namespace GQUIC {
	   class GQUIC_Conn;
   }
}

namespace analyzer { namespace gquic {

class GQUIC_Analyzer : public zeek::analyzer::Analyzer {
public:
	GQUIC_Analyzer(zeek::Connection* conn);
	virtual ~GQUIC_Analyzer();

	virtual void Done();
	virtual void DeliverPacket(int len, const u_char* data, bool orig,
	                           uint64_t seq, const zeek::IP_Hdr* ip,
	                           int caplen);

	static zeek::analyzer::Analyzer* Instantiate(zeek::Connection* conn)
		{ return new GQUIC_Analyzer(conn); }

protected:
	int did_session_done;

	bool orig_done;
	bool resp_done;

	zeek::analyzer::pia::PIA_UDP* pia;
	binpac::GQUIC::GQUIC_Conn* interp;
};

} } // namespace analyzer::* 

#endif
