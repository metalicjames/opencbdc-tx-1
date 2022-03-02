// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_RUNNER_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_RUNNER_H_

#include "3pc/agent/runners/interface.hpp"
#include "host.hpp"

#include <evmc/evmc.h>
#include <thread>

namespace cbdc::threepc::agent::runner {
    class evm_runner : public interface {
      public:
        evm_runner(std::shared_ptr<logging::log> logger,
                   runtime_locking_shard::value_type function,
                   parameter_type param,
                   run_callback_type result_callback,
                   try_lock_callback_type try_lock_callback);

        ~evm_runner() override;

        evm_runner(const evm_runner&) = delete;
        auto operator=(const evm_runner&) -> evm_runner& = delete;
        evm_runner(evm_runner&&) = delete;
        auto operator=(evm_runner&&) -> evm_runner& = delete;

        auto run() -> bool override;

        static constexpr auto initial_lock_type = broker::lock_type::write;

      private:
        std::shared_ptr<evmc::VM> m_vm;
        std::thread m_evm_thread;

        void exec(const evmc_message& msg,
                  const std::shared_ptr<evm_host>& host);
    };
}

#endif
