project(evm_runner)

add_library(evm_runner impl.cpp
                       host.cpp
                       format.cpp)
