
module GQUIC;

export {

	## Contains information related to the contents of the Public Header
	## portion of GQUIC Regular Packets.
	type PublicHeader: record {
		## The packet number.
		pkt_num: count;

		## Whether the multipath bit of Public Flags is set.
		multipath: bool;

		## Whether the reserved bit of Public Flags is set.
		reserved: bool;

		## The Connection ID field if present (a bit in the Public Flags
		## indicates this).
		cid: string &optional;

		## The version parsed as a numerical value.
		## E.g. for "Q039" this will be 39.
		## Only set when the version bit of the Public Flags is set
		## for in the client-side packets (servers never send this).
		version: count &optional;

		## The Diversification Nonce field if present.
		## (Clients may actually set the nonce bit, but not have the
		## nonce field present).
		nonce: string &optional;

	};
}
