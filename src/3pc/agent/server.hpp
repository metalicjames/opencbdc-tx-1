// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_SERVER_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_SERVER_H_

#include "agent/impl.hpp"
#include "broker/interface.hpp"
#include "directory/interface.hpp"
#include "interface.hpp"
#include "messages.hpp"
#include "util/common/blocking_queue.hpp"
#include "util/rpc/async_server.hpp"

#include <atomic>
#include <thread>

namespace cbdc::threepc::agent::rpc {
    /// RPC server for a agent. Manages retrying function execution if it fails
    /// due to a transient error.
    class server {
      public:
        using server_type = cbdc::rpc::async_server<request, response>;

        /// Constructor. Registers the agent implementation with the
        /// RPC server using a request handler callback.
        /// \param srv pointer to an asynchronous RPC server.
        /// \param broker broker instance.
        /// \param log log instance.
        server(std::unique_ptr<server_type> srv,
               std::shared_ptr<broker::interface> broker,
               std::shared_ptr<logging::log> log);

        ~server();

        server(const server&) = delete;
        auto operator=(const server&) -> server& = delete;
        server(server&&) = delete;
        auto operator=(server&&) -> server& = delete;

      private:
        std::unique_ptr<server_type> m_srv;
        std::shared_ptr<broker::interface> m_broker;
        std::shared_ptr<logging::log> m_log;

        mutable std::mutex m_agents_mut;
        std::atomic<size_t> m_next_id{};
        std::unordered_map<size_t, std::shared_ptr<agent::impl>> m_agents;

        blocking_queue<size_t> m_cleanup_queue;
        std::thread m_cleanup_thread;

        blocking_queue<size_t> m_retry_queue;
        std::thread m_retry_thread;

        auto request_handler(request req,
                             server_type::response_callback_type callback)
            -> bool;
    };
}

#endif
