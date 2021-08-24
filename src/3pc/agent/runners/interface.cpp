// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "interface.hpp"

namespace cbdc::threepc::agent::runner {
    interface::interface(std::shared_ptr<logging::log> logger,
                         const cbdc::threepc::config& cfg,
                         runtime_locking_shard::value_type function,
                         parameter_type param,
                         bool dry_run,
                         run_callback_type result_callback,
                         try_lock_callback_type try_lock_callback,
                         std::shared_ptr<secp256k1_context> secp,
                         std::shared_ptr<thread_pool> t_pool,
                         std::shared_ptr<cbdc::telemetry> tel,
                         ticket_number_type ticket_number)
        : m_log(std::move(logger)),
          m_cfg(cfg),
          m_function(std::move(function)),
          m_param(std::move(param)),
          m_dry_run(dry_run),
          m_result_callback(std::move(result_callback)),
          m_try_lock_callback(std::move(try_lock_callback)),
          m_secp(std::move(secp)),
          m_threads(std::move(t_pool)),
          m_tel(std::move(tel)),
          m_ticket_number(ticket_number) {}
}
