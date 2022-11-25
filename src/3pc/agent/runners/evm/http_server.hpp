// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_HTTP_SERVER_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_HTTP_SERVER_H_

#include "3pc/agent/runners/evm/impl.hpp"
#include "agent/impl.hpp"
#include "agent/server_interface.hpp"
#include "broker/interface.hpp"
#include "directory/interface.hpp"
#include "messages.hpp"
#include "util/common/blocking_queue.hpp"
#include "util/common/thread_pool.hpp"
#include "util/rpc/http/json_rpc_http_server.hpp"

#include <atomic>
#include <secp256k1.h>
#include <thread>

namespace cbdc::threepc::agent::rpc {
    /// RPC server for a agent. Manages retrying function execution if it fails
    /// due to a transient error.
    class http_server : public server_interface {
      public:
        /// Type alias for the underlying RPC server.
        using server_type = cbdc::rpc::json_rpc_http_server;

        /// Constructor. Registers the agent implementation with the
        /// RPC server using a request handler callback.
        /// \param srv pointer to an HTTP JSON-RPC server.
        /// \param broker broker instance.
        /// \param log log instance.
        /// \param cfg system configuration options.
        http_server(std::unique_ptr<server_type> srv,
                    std::shared_ptr<broker::interface> broker,
                    std::shared_ptr<logging::log> log,
                    const cbdc::threepc::config& cfg);

        /// Stops listening for incoming connections, waits for existing
        /// connections to drain.
        ~http_server() override;

        /// Starts listening for incoming connections and processing requests.
        /// \return true if listening was sucessful.
        auto init() -> bool override;

        http_server(const http_server&) = delete;
        auto operator=(const http_server&) -> http_server& = delete;
        http_server(http_server&&) = delete;
        auto operator=(http_server&&) -> http_server& = delete;

      private:
        std::unique_ptr<server_type> m_srv;

        auto request_handler(const std::string& method,
                             const Json::Value& params,
                             const server_type::result_callback_type& callback)
            -> bool;

        auto handle_send_raw_transaction(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;

        auto handle_get_transaction_count(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;

        auto handle_chain_id(Json::Value params,
                             const server_type::result_callback_type& callback)
            -> bool;

        auto handle_call(Json::Value params,
                         const server_type::result_callback_type& callback)
            -> bool;

        auto handle_send_transaction(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;

        auto
        handle_estimate_gas(Json::Value params,
                            const server_type::result_callback_type& callback)
            -> bool;

        auto handle_client_version(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;
        auto
        handle_gas_price(Json::Value params,
                         const server_type::result_callback_type& callback)
            -> bool;

        auto handle_get_code(Json::Value params,
                             const server_type::result_callback_type& callback)
            -> bool;
        auto
        handle_get_balance(Json::Value params,
                           const server_type::result_callback_type& callback)
            -> bool;
        auto handle_accounts(Json::Value params,
                             const server_type::result_callback_type& callback)
            -> bool;

        auto handle_get_transaction_by_hash(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;

        auto handle_get_transaction_receipt(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;

        auto
        handle_not_supported(Json::Value params,
                             const server_type::result_callback_type& callback)
            -> bool;

        auto
        handle_block_number(Json::Value params,
                            const server_type::result_callback_type& callback)
            -> bool;
        auto
        handle_get_block(Json::Value params,
                         const server_type::result_callback_type& callback)
            -> bool;
        auto handle_get_block_txcount(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;
        auto
        handle_get_block_tx(Json::Value params,
                            const server_type::result_callback_type& callback)
            -> bool;
        auto
        handle_fee_history(Json::Value params,
                           const server_type::result_callback_type& callback)
            -> bool;
        auto handle_get_logs(Json::Value params,
                             const server_type::result_callback_type& callback)
            -> bool;
        auto handle_get_storage_at(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;

        auto handle_sha3(Json::Value params,
                         const server_type::result_callback_type& callback)
            -> bool;

        auto handle_error(Json::Value params,
                          const server_type::result_callback_type& callback,
                          int code,
                          std::string message) -> bool;

        auto handle_number(Json::Value params,
                           const server_type::result_callback_type& callback,
                           uint64_t number) -> bool;

        auto handle_boolean(Json::Value params,
                            const server_type::result_callback_type& callback,
                            bool result) -> bool;

        auto handle_decode_raw_transaction(
            Json::Value params,
            const server_type::result_callback_type& callback) -> bool;

        auto
        parse_evm_log_query(Json::Value params,
                            const server_type::result_callback_type& callback)
            -> std::optional<threepc::agent::runner::evm_log_query>;

        auto fetch_block(Json::Value params,
                         const server_type::result_callback_type& callback,
                         std::function<void(interface::exec_return_type,
                                            cbdc::buffer)> res_cb) -> bool;

        auto exec_tx(const server_type::result_callback_type& callback,
                     runner::evm_runner_function f_type,
                     cbdc::buffer& runner_params,
                     bool dry_run,
                     std::function<void(interface::exec_return_type)> res_cb)
            -> bool;
    };
}

#endif
