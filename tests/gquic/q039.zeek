# @TEST-EXEC: zeek -C -r $TRACES/gquic-q039.pcap gquic_events >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep gquic conn.log
