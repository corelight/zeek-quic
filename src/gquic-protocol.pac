# Google QUIC docs: https://www.chromium.org/quic
# Wire format spec: https://docs.google.com/document/d/1WJvyZflAO2pq77yOLbp9NsGjC1CHetAXV8I0fQe-B_U/edit
#
# At time of writing, the IETF draft of QUIC had already significantly
# diverged in terms of wire format from the Google version of QUIC and it
# is likely the above links will eventually change to reflect the actual
# QUIC standard.  i.e. Google is slowly working to migrate GQUIC to
# track the changes made by the IETF.

# For reference, the following message format was written on May 4, 2018
# and tested against GQUIC Version "Q039".  The wire format specification
# document was also not completely up to date at that time, with it only
# acknowleding the changes through version Q036.  e.g. the doc still claimed
# a little-endian byte order even through Q039 made the switch to big-endian.

type GQUIC_Packet(is_orig: bool) = record {
	flags: PublicFlags(is_orig);
	cid:   ConnectionID(flags);
	content: case flags.packet_type of {
		NEGOTIATION -> neg_pkt: VersionNegotiationPacket(flags, cid, is_orig);
		RESET ->       res_pkt: PublicResetPacket(flags, cid, is_orig);
		REGULAR ->     reg_pkt: RegularPacket(flags, cid, is_orig);
		default ->     nil_pkt: empty;
	};
} &byteorder = bigendian; # NOTE: versions before Q039 are little-endian

type PublicFlags(is_orig: bool) = record {
	byte: uint8;
}
&let {
	# Clients may set the nonce bit in the header even though there is no
	# nonce in the message.  See:
	# https://groups.google.com/a/chromium.org/forum/#!topic/proto-quic/kQVDZal_iwo

	have_version: bool   = (byte & 0x01) == 0x01;
	is_negotiate: bool   = (byte & 0x01) == 0x01 && ! is_orig;
	is_reset:     bool   = (byte & 0x02) == 0x02;
    have_nonce:   bool   = (byte & 0x04) == 0x04 && ! is_orig;
	have_conn_id: bool   = (byte & 0x08) == 0x08;
	pkt_num_size: uint8  = (byte & 0x30);
	is_multipath: bool   = (byte & 0x40) == 0x40;
	reserved_bit: bool   = (byte & 0x80) == 0x80;
	packet_type:  int    = (is_reset     ? RESET :
	                       (is_negotiate ? NEGOTIATION :
	                        REGULAR));
};

type ConnectionID(flags: PublicFlags) = record {
	present: case flags.have_conn_id of {
		true  -> bytes: uint8[8];
		false -> nil:   empty;
	};
};

type RegularPacket(flags: PublicFlags,
                   cid: ConnectionID, is_orig: bool)= record {
	version: case flags.have_version of {
		true  -> version_val: uint8[4];
		false -> version_nil: empty;
	};

	nonce: case flags.have_nonce of {
		true  -> nonce_val: uint8[32];
		false -> nonce_nil: empty;
	};

	pkt_num_bytes: case flags.pkt_num_size of {
		0x00    -> pkt_num_bytes1: uint8[1];
		0x10    -> pkt_num_bytes2: uint8[2];
		0x20    -> pkt_num_bytes4: uint8[4];
		0x30    -> pkt_num_bytes6: uint8[6];
		default -> pkt_num_bytesx: empty; # not possible, all 4 cases handled 
	};
};

type VersionNegotiationPacket(flags: PublicFlags,
                              cid: ConnectionID, is_orig: bool) = record {
	version_list: bytestring &restofdata;
};

type PublicResetPacket(flags: PublicFlags,
                       cid: ConnectionID, is_orig: bool) = record {
	tag: uint8[4];
	# Remaining bytes are a variable length tag value map.
	data: bytestring &restofdata &transient;
};

enum PacketType {
	NEGOTIATION,
	RESET,
	REGULAR,
};
