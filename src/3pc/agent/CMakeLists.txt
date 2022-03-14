project(agent)

add_library(agent impl.cpp
                  interface.cpp
                  server.cpp
                  client.cpp
                  format.cpp)

add_executable(agentd agentd.cpp)
target_link_libraries(agentd agent
                             broker
                             directory
                             ticket_machine
                             runtime_locking_shard
                             phasetwo
                             evm_runner
                             runners
                             rpc
                             network
                             serialization
                             common
                             crypto
                             secp256k1
                             ${LUA_LIBRARY}
                             ${CMAKE_THREAD_LIBS_INIT})

add_subdirectory(runners)
