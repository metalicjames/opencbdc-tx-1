// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_RAFT_RPC_SERVER_H_
#define CBDC_UNIVERSE0_SRC_RAFT_RPC_SERVER_H_

#include "node.hpp"
#include "util/rpc/async_server.hpp"

namespace cbdc::raft::rpc {
    /// Generic RPC server for raft nodes for which the replicated state
    /// machine handles the request processing logic. Replicates
    /// requests to the cluster which executes them via its state machine. Once
    /// state machine execution completes, the raft node returns a batch of
    /// results for previous RPCs. Handles the case where results for an RPC
    /// are returned asynchronously from the state machine (usually after a
    /// subsequent RPC).
    template<typename Request, typename Response>
    class batch_server
        : public cbdc::rpc::async_server<Request, Response, buffer, buffer> {
      public:
        using server_type
            = cbdc::rpc::async_server<Request, Response, buffer, buffer>;

        /// Registers the raft node whose state machine handles RPC requests
        /// for this server.
        /// \param impl pointer to the raft node.
        /// \see cbdc::rpc::server
        void register_raft_node(std::shared_ptr<node> impl) {
            m_impl = std::move(impl);
            server_type::register_handler_callback(
                [&](Request req,
                    typename server_type::response_callback_type resp_cb) {
                    return request_handler(std::move(req), std::move(resp_cb));
                });
        }

      private:
        std::shared_ptr<node> m_impl;

        using replication_return_type
            = std::optional<std::vector<std::pair<size_t, Response>>>;
        using replication_request_type = std::pair<size_t, Request>;

        std::unordered_map<size_t,
                           typename server_type::response_callback_type>
            m_callbacks;
        mutable std::mutex m_callbacks_mut;
        std::atomic<size_t> m_request_id{};

        auto request_handler(
            Request request,
            typename server_type::response_callback_type response_callback)
            -> bool {
            if(!m_impl->is_leader()) {
                return false;
            }

            auto req_id = m_request_id++;
            auto req = replication_request_type{req_id, request};
            auto new_log = make_buffer<replication_request_type,
                                       nuraft::ptr<nuraft::buffer>>(req);
            {
                std::unique_lock l(m_callbacks_mut);
                m_callbacks.emplace(req_id, response_callback);
            }

            auto success = m_impl->replicate(
                new_log,
                [&, req_id, resp_cb = response_callback](
                    result_type& r,
                    nuraft::ptr<std::exception>& err) {
                    if(err) {
                        call_callback(req_id, std::nullopt);
                        return;
                    }

                    const auto res = r.get();
                    if(!res) {
                        call_callback(req_id, std::nullopt);
                        return;
                    }

                    auto ret = from_buffer<replication_return_type>(*res);
                    if(!ret.has_value()) {
                        // TODO: probably should be fatal, indicates a bug
                        call_callback(req_id, std::nullopt);
                        return;
                    }

                    if(!ret->has_value()) {
                        call_callback(req_id, std::nullopt);
                        return;
                    }

                    for(auto& resp : **ret) {
                        call_callback(resp.first, resp.second);
                    }
                });

            return success;
        }

        void call_callback(cbdc::rpc::request_id_type req_id,
                           std::optional<Response> resp) {
            auto cb = [&]() {
                std::unique_lock l(m_callbacks_mut);
                return m_callbacks.extract(req_id);
            }();
            if(cb) {
                cb.mapped()(resp);
            }
        }
    };
}

#endif
