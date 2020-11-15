# @TEST-EXEC: bro -NN Corelight::GQUIC |sed -e 's/version.*)/version)/g' >output
# @TEST-EXEC: btest-diff output
