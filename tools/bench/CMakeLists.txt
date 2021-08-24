project(bench)

include_directories(../../src ../../3rdparty ../../3rdparty/secp256k1/include ../../src/phase_two)

add_executable(twophase-gen twophase_gen.cpp)
target_link_libraries(twophase-gen sentinel
                                   sentinel_interface
                                   locking_shard
                                   coordinator
                                   transaction
                                   rpc
                                   network
                                   common
                                   serialization
                                   crypto
                                   ${NURAFT_LIBRARY}
                                   secp256k1
                                   ${CMAKE_THREAD_LIBS_INIT})

add_executable(atomizer-cli-watchtower atomizer-cli-watchtower.cpp)
target_link_libraries(atomizer-cli-watchtower watchtower
                                              atomizer
                                              sentinel
                                              sentinel_interface
                                              rpc
                                              transaction
                                              network
                                              common
                                              serialization
                                              crypto
                                              secp256k1
                                              ${NURAFT_LIBRARY}
                                              ${CMAKE_THREAD_LIBS_INIT})

add_executable(phasetwo_bench phasetwo_bench.cpp)
target_link_libraries(phasetwo_bench broker
                                     directory
                                     runtime_locking_shard
                                     ticket_machine
                                     phasetwo
                                     transactions
                                     agent
                                     rpc
                                     network
                                     common
                                     serialization
                                     crypto
                                     secp256k1
                                     ${LUA_LIBRARY}
                                     ${CMAKE_THREAD_LIBS_INIT})
