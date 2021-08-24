// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "util.hpp"

#include <future>

namespace cbdc::threepc {
    auto put_row(const std::shared_ptr<broker::interface>& broker,
                 broker::key_type key,
                 broker::value_type value,
                 const std::function<void(bool)>& result_callback) -> bool {
        auto begin_res = broker->begin([=](auto begin_ret) {
            if(!std::holds_alternative<
                   cbdc::threepc::ticket_machine::ticket_number_type>(
                   begin_ret)) {
                result_callback(false);
                return;
            }
            auto ticket_number
                = std::get<cbdc::threepc::ticket_machine::ticket_number_type>(
                    begin_ret);
            auto lock_res = broker->try_lock(
                ticket_number,
                key,
                cbdc::threepc::runtime_locking_shard::lock_type::write,
                [=](auto try_lock_res) {
                    if(!std::holds_alternative<cbdc::buffer>(try_lock_res)) {
                        result_callback(false);
                        return;
                    }
                    auto commit_res = broker->commit(
                        ticket_number,
                        {{key, value}},
                        [=](auto commit_ret) {
                            if(commit_ret.has_value()) {
                                result_callback(false);
                                return;
                            }
                            auto finish_res = broker->finish(
                                ticket_number,
                                [=](auto finish_ret) {
                                    result_callback(!finish_ret.has_value());
                                });
                            if(!finish_res) {
                                result_callback(false);
                                return;
                            }
                        });
                    if(!commit_res) {
                        result_callback(false);
                        return;
                    }
                });
            if(!lock_res) {
                result_callback(false);
                return;
            }
        });
        return begin_res;
    }
}
