// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "state_machine.hpp"

#include "format.hpp"
#include "util/rpc/format.hpp"
#include "util/serialization/format.hpp"

namespace cbdc::threepc::runtime_locking_shard {
    state_machine::state_machine(std::shared_ptr<logging::log> logger)
        : m_logger(std::move(logger)) {
        register_handler_callback([&](request_type req) {
            process_request(std::move(req));
            return m_responses;
        });
        m_shard = std::make_unique<impl>(m_logger);
    }

    auto state_machine::commit(uint64_t log_idx, nuraft::buffer& data)
        -> nuraft::ptr<nuraft::buffer> {
        m_last_committed_idx = log_idx;
        m_responses.clear();

        auto resp = blocking_call(data);
        if(!resp.has_value()) {
            // TODO: This would only happen if there was a deserialization
            // error with the request. Maybe we should abort here as such an
            // event would imply a bug in the coordinator.
            return nullptr;
        }

        return resp.value();
    }

    auto state_machine::apply_snapshot(nuraft::snapshot& /* s */) -> bool {
        return false;
    }

    auto state_machine::last_snapshot() -> nuraft::ptr<nuraft::snapshot> {
        return nullptr;
    }

    auto state_machine::last_commit_index() -> uint64_t {
        return m_last_committed_idx;
    }

    void state_machine::create_snapshot(
        nuraft::snapshot& /* s */,
        nuraft::async_result<bool>::handler_type& when_done) {
        nuraft::ptr<std::exception> except(nullptr);
        bool ret = false;
        when_done(ret, except);
    }

    void state_machine::process_request(request_type req) {
        [[maybe_unused]] auto success = std::visit(
            overloaded{[&](const rpc::try_lock_request& msg) {
                           return m_shard->try_lock(
                               msg.m_ticket_number,
                               msg.m_broker_id,
                               msg.m_key,
                               msg.m_locktype,
                               [&, req_id = req.first](
                                   interface::try_lock_return_type ret) {
                                   m_responses.emplace_back(
                                       response_type{req_id, ret});
                               });
                       },
                       [&](const rpc::prepare_request& msg) {
                           return m_shard->prepare(
                               msg.m_ticket_number,
                               msg.m_state_updates,
                               [&, req_id = req.first](
                                   interface::prepare_return_type ret) {
                                   m_responses.emplace_back(
                                       response_type{req_id, ret});
                               });
                       },
                       [&](rpc::commit_request msg) {
                           return m_shard->commit(
                               msg.m_ticket_number,
                               [&, req_id = req.first](
                                   interface::commit_return_type ret) {
                                   m_responses.emplace_back(
                                       response_type{req_id, ret});
                               });
                       },
                       [&](rpc::rollback_request msg) {
                           return m_shard->rollback(
                               msg.m_ticket_number,
                               [&, req_id = req.first](
                                   interface::rollback_return_type ret) {
                                   m_responses.emplace_back(
                                       response_type{req_id, ret});
                               });
                       },
                       [&](rpc::finish_request msg) {
                           return m_shard->finish(
                               msg.m_ticket_number,
                               [&, req_id = req.first](
                                   interface::finish_return_type ret) {
                                   m_responses.emplace_back(
                                       response_type{req_id, ret});
                               });
                       },
                       [&](rpc::get_tickets_request msg) {
                           return m_shard->get_tickets(
                               msg.m_broker_id,
                               [&, req_id = req.first](
                                   interface::get_tickets_return_type ret) {
                                   m_responses.emplace_back(
                                       response_type{req_id, ret});
                               });
                       }},
            req.second);
        assert(success);
    }
}
