// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_RUNTIME_LOCKING_SHARD_CONTROLLER_H_
#define CBDC_UNIVERSE0_SRC_3PC_RUNTIME_LOCKING_SHARD_CONTROLLER_H_

#include "impl.hpp"
#include "state_machine.hpp"
#include "util/raft/node.hpp"
#include "util/raft/rpc_batch_server.hpp"
#include "util/rpc/tcp_server.hpp"

namespace cbdc::threepc::runtime_locking_shard {
    /// Manages a replicated runtime locking shard using Raft.
    class controller {
      public:
        /// Constructor.
        /// \param component_id ID of the shard cluster.
        /// \param node_id node ID within the cluster.
        /// \param server_endpoint RPC endpoint of the node.
        /// \param raft_endpoints vector of raft endpoints for nodes in the
        ///                       cluster.
        /// \param logger log to use for output.
        controller(size_t component_id,
                   size_t node_id,
                   network::endpoint_t server_endpoint,
                   std::vector<network::endpoint_t> raft_endpoints,
                   std::shared_ptr<logging::log> logger);
        ~controller() = default;

        controller() = delete;
        controller(const controller&) = delete;
        auto operator=(const controller&) -> controller& = delete;
        controller(controller&&) = delete;
        auto operator=(controller&&) -> controller& = delete;

        /// Initializes the shard. Starts the raft instance and joins the raft
        /// cluster.
        /// \return true if initialization was successful.
        auto init() -> bool;

      private:
        auto raft_callback(nuraft::cb_func::Type type,
                           nuraft::cb_func::Param* param)
            -> nuraft::cb_func::ReturnCode;

        std::shared_ptr<logging::log> m_logger;

        std::shared_ptr<state_machine> m_state_machine;
        std::shared_ptr<raft::node> m_raft_serv;
        std::unique_ptr<cbdc::rpc::tcp_server<
            raft::rpc::batch_server<rpc::request, rpc::response>>>
            m_server;

        std::vector<network::endpoint_t> m_raft_endpoints;
        network::endpoint_t m_server_endpoint;
    };
}

#endif
