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
                         run_callback_type result_callback,
                         try_lock_callback_type try_lock_callback)
        : m_log(std::move(logger)),
          m_cfg(cfg),
          m_function(std::move(function)),
          m_param(std::move(param)),
          m_result_callback(std::move(result_callback)),
          m_try_lock_callback(std::move(try_lock_callback)) {}
}
