// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_UTIL_H_
#define CBDC_UNIVERSE0_SRC_3PC_UTIL_H_

#include "util/common/config.hpp"

namespace cbdc::threepc {
    /// Configuration parameters for a phase two system.
    struct config {
        /// RPC endpoints for the nodes in the ticket machine raft cluster.
        std::vector<network::endpoint_t> m_ticket_machine_endpoints;
        /// RPC endpoints for the agents.
        std::vector<network::endpoint_t> m_agent_endpoints;
        /// RPC endpoints for the nodes in the shard raft clusters.
        std::vector<std::vector<network::endpoint_t>> m_shard_endpoints;
        /// ID of the component the instance should be.
        size_t m_component_id;
        /// ID of the node within the component the instance should be, if
        /// applicable.
        std::optional<size_t> m_node_id;
        /// The dynamic library to load for the EVM implementation. When using
        /// evmone, this would be "libevmone.so" for Linux, "libevmone.dylib"
        /// for Mac and "evmone.dll" for Windows - assuming they are in the
        /// path
        std::optional<std::string> m_evm_library;
    };

    /// Reads the configuration parameters from the program arguments.
    /// \param argc number of program arguments.
    /// \param argv program arguments.
    /// \return configuration parametrs or std::nullopt if there was an error
    ///         while parsing the arguments.
    auto read_config(int argc, char** argv) -> std::optional<config>;
}

#endif
