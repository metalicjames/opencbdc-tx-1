// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_RUNNER_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_RUNNER_H_

#include "evm_host.hpp"
#include "runner.hpp"

#include <evmc/evmc.h>
#include <thread>

namespace cbdc::threepc::agent {
    class evm_runner {
      public:
        evm_runner(std::shared_ptr<logging::log> logger,
                   runtime_locking_shard::value_type function,
                   parameter_type param,
                   runner::run_callback_type result_callback,
                   runner::try_lock_callback_type try_lock_callback);

        ~evm_runner();

        auto run() -> bool;

      private:
        std::shared_ptr<logging::log> m_log;
        runtime_locking_shard::value_type m_function;
        parameter_type m_param;
        runner::run_callback_type m_result_callback;
        runner::try_lock_callback_type m_try_lock_callback;

        std::thread m_evm_thread;
        std::unique_ptr<host> m_evm_host;

        std::shared_ptr<evmc_vm> m_vm;
    };
}

#endif
