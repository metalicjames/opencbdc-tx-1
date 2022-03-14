project(evm_runner)

add_library(evm_runner impl.cpp
                       hash.cpp
                       host.cpp
                       format.cpp
                       rlp.cpp
                       rlp_writer.cpp
                       util.cpp)

target_link_libraries(evm_runner ${KECCAK_LIBRARY}
                                 ${EVMC_HEX_LIBRARY}
                                 ${EVMONE_LIBRARY})
