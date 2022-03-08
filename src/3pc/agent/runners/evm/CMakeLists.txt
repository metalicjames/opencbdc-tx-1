project(evm_runner)

find_library(KECCAK_LIBRARY keccak REQUIRED)

add_library(evm_runner impl.cpp
                       hash.cpp
                       host.cpp
                       format.cpp
                       rlp.cpp
                       rlp_writer.cpp
                       util.cpp)

target_link_libraries(evm_runner ${KECCAK_LIBRARY})
