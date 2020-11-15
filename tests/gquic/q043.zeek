# @TEST-EXEC: bro -C -r $TRACES/gquic-q043.pcap gquic_events >output
# @TEST-EXEC: btest-diff output
# @TEST-EXEC: grep gquic conn.log
