
cxx_test(PRETTY_NAME "core::network" BIN_NAME "test_network" SOURCES "toxcore/test_network.cpp" LIBS toxcore)
cxx_test(PRETTY_NAME "core::crypto::core" BIN_NAME "test_crypto_core" SOURCES "toxcore/test_crypto_core.cpp" LIBS toxcore)
cxx_test(PRETTY_NAME "core::crypto::ping_array" BIN_NAME "test_ping_array" SOURCES "toxcore/test_ping_array.cpp" LIBS toxcore)
