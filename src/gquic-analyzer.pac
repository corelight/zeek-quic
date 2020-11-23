%extern{
	#include <cctype>
	#include <unordered_set>
	#include "consts.bif.h"
	#include "types.bif.h"
	#include "Scope.h"
%}

%header{
%}

%code{
%}

refine connection GQUIC_Conn += {

	%member{
		bool saw_server_pkt1;
		uint16 last_known_client_version;
		std::unordered_set<uint16> potential_client_versions;

		void confirm()
			{
			bro_analyzer()->ProtocolConfirmation();

			if ( BifConst::GQUIC::skip_after_confirm )
				bro_analyzer()->SetSkip(true);
			}

		uint16 extract_gquic_version(const uint8* version_bytes)
			{
			if ( version_bytes[0] != 'Q' )
				{
				bro_analyzer()->ProtocolViolation("invalid GQUIC Version",
				    reinterpret_cast<const char*>(version_bytes), 4);
				return 0;
				}

			for ( auto i = 1u; i < 4; ++i )
				{
				if ( ! isdigit(version_bytes[i]) )
					{
					bro_analyzer()->ProtocolViolation(
					    "invalid GQUIC Version",
				        reinterpret_cast<const char*>(version_bytes), 4);
					return 0;
					}
				}

			uint16 rval = 0;
			rval += (version_bytes[1] - 0x30) * 100;
			rval += (version_bytes[2] - 0x30) * 10;
			rval += (version_bytes[3] - 0x30);
			return rval;
			}
	%}

	%init{
		saw_server_pkt1 = false;
		last_known_client_version = 0;
	%}

	%cleanup{
	%}

	function process_packet(pkt: GQUIC_Packet, is_orig: bool): bool
		%{
		switch ( ${pkt.flags.packet_type} ) {
		case NEGOTIATION:
			{
			auto vlist = ${pkt.neg_pkt.version_list};

			if ( vlist.length() % 4 != 0 )
				{
				bro_analyzer()->ProtocolViolation(
				    "invalid GQUIC Version Negotation list",
				    reinterpret_cast<const char*>(vlist.data()),
				    vlist.length());
				return true;
				}

			std::vector<uint16> parsed_version_list;
			parsed_version_list.reserve(vlist.length() / 4);

			for ( auto i = 0; i < vlist.length(); i += 4 )
				{
				auto ptr = reinterpret_cast<const uint8*>(vlist.begin() + i);
				auto parsed_version = extract_gquic_version(ptr);

				if ( parsed_version == 0 )
					return true;

				parsed_version_list.emplace_back(parsed_version);
				}

			if ( last_known_client_version )
				confirm();

			if ( gquic_version_negotiation )
				{
				static auto vt = lookup_ID("index_vec", "GLOBAL")->Type()->AsVectorType();
				auto vv = new VectorVal(vt);

				for ( auto i = 0u; i < parsed_version_list.size(); ++i )
					vv->Assign(vv->Size(), val_mgr->GetCount(parsed_version_list[i]));

				BifEvent::generate_gquic_version_negotiation(
				    bro_analyzer(), bro_analyzer()->Conn(), is_orig, vv);
				}
			}
			break;
		case RESET:
			{
			if ( gquic_reset )
				BifEvent::generate_gquic_reset(bro_analyzer(),
											   bro_analyzer()->Conn(),
											   is_orig);
			}
			break;
		case REGULAR:
			{
			auto pkt_num = 0u;
			auto pkt_version = get_gquic_version(${pkt.reg_pkt});

			if ( is_orig )
				{
				if ( pkt_version )
					{
					last_known_client_version = pkt_version;
					auto p = potential_client_versions.emplace(pkt_version);

					if ( gquic_client_version && p.second )
						BifEvent::generate_gquic_client_version(
						    bro_analyzer(),
						    bro_analyzer()->Conn(),
						    pkt_version);
					}

				pkt_num = get_packet_number(${pkt.reg_pkt},
				                            last_known_client_version);

				if ( last_known_client_version && saw_server_pkt1 )
					confirm();
				}
			else
				{
				pkt_num = get_packet_number(${pkt.reg_pkt},
				                            last_known_client_version);

				if ( pkt_num == 1 )
					saw_server_pkt1 = true;

				if ( last_known_client_version && saw_server_pkt1 )
					confirm();
				}

			if ( gquic_packet )
				{
				auto rv = new RecordVal(BifType::Record::GQUIC::PublicHeader);
				rv->Assign(0, val_mgr->GetCount(pkt_num));
				rv->Assign(1, val_mgr->GetBool(${pkt.flags.is_multipath}));
				rv->Assign(2, val_mgr->GetBool(${pkt.flags.reserved_bit}));

				if ( ${pkt.cid}->present_case_index() )
					{
					auto bytes = ${pkt.cid.bytes};
					auto ptr = reinterpret_cast<const char*>(bytes->data());
					rv->Assign(3, new StringVal(bytes->size(), ptr));
					}

				if ( ${pkt.reg_pkt}->version_case_index() )
					rv->Assign(4, val_mgr->GetCount(pkt_version));

				if ( ${pkt.reg_pkt}->nonce_case_index() )
					{
					auto bytes = ${pkt.reg_pkt.nonce_val};
					auto ptr = reinterpret_cast<const char*>(bytes->data());
					rv->Assign(5, new StringVal(bytes->size(), ptr));
					}

				BifEvent::generate_gquic_packet(bro_analyzer(),
				                                bro_analyzer()->Conn(),
				                                is_orig, rv);
				}
			}
			break;
		default:
			break;
		}

		return true;
		%}

	function get_gquic_version(pkt: RegularPacket): uint16
		%{
		if ( ! pkt->version_case_index() )
			return 0;

		return extract_gquic_version(${pkt.version_val}->data());
		%}

	function get_packet_number(pkt: RegularPacket, version: uint16): uint64
		%{
		return convert_packet_bytes(get_packet_number_bytes(pkt), version);
		%}

	function get_packet_number_bytes(pkt: RegularPacket): uint8[]
		%{
		switch ( pkt->pkt_num_bytes_case_index() ) {
			case 0x00:
				return ${pkt.pkt_num_bytes1};
			case 0x10:
				return ${pkt.pkt_num_bytes2};
			case 0x20:
				return ${pkt.pkt_num_bytes4};
			case 0x30:
				return ${pkt.pkt_num_bytes6};
			default:
				assert(false);
		}
		return nullptr;
		%}

	function convert_packet_bytes(bytes: uint8[], version: uint16): uint64
		%{
		uint64 rval = 0;
		uint8* byte_ptr = reinterpret_cast<uint8*>(&rval);
		byte_ptr += sizeof(rval) - bytes->size();

		for ( auto i = 0u; i < bytes->size(); ++i )
			{
			auto byte = (*bytes)[i];
			*byte_ptr = byte;
			++byte_ptr;
			}

		// Version 0 essentially means we haven't seen a version yet, so
		// assume a recent version of GQUIC.
		auto gquic_is_big_endian = version == 0 || version >= 39;

		if ( gquic_is_big_endian )
			rval = ntohll(rval);
		else
			{
#ifdef WORDS_BIGENDIAN
			uint64 tmp;
			uint8* src = reinterpret_cast<uint8*>(&rval);
			uint8* dst = reinterpret_cast<uint8*>(&tmp);
			dst[0] = src[7];
			dst[1] = src[6];
			dst[2] = src[5];
			dst[3] = src[4];
			dst[4] = src[3];
			dst[5] = src[2];
			dst[6] = src[1];
			dst[7] = src[0];
			rval = tmp;
#endif
			}

		return rval;
		%}
};

refine typeattr GQUIC_Packet += &let {
	proc = $context.connection.process_packet(this, is_orig);
};
