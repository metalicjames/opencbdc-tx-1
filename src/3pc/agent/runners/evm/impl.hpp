// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_RUNNER_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_RUNNER_H_

#include "3pc/agent/runners/interface.hpp"
#include "3pc/util.hpp"
#include "host.hpp"

#include <evmc/evmc.h>
#include <secp256k1.h>
#include <thread>

namespace cbdc::threepc::agent::runner {
    enum class evm_runner_function : uint8_t {
        execute_transaction,
        read_account,
        dryrun_transaction,
        read_account_code,
    };
    class evm_runner : public interface {
      public:
        evm_runner(std::shared_ptr<logging::log> logger,
                   const cbdc::threepc::config& cfg,
                   runtime_locking_shard::value_type function,
                   parameter_type param,
                   bool dry_run,
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
        std::unique_ptr<secp256k1_context,
                        decltype(&secp256k1_context_destroy)>
            m_secp{secp256k1_context_create(SECP256K1_CONTEXT_SIGN
                                            | SECP256K1_CONTEXT_VERIFY),
                   &secp256k1_context_destroy};

        uint64_t m_gas_limit{};

        void exec(const evmc_message& msg,
                  const std::shared_ptr<evm_host>& host);
        auto run_execute_real_transaction() -> bool;
        auto run_execute_dryrun_transaction() -> bool;
        auto run_get_account_code() -> bool;
        auto run_execute_transaction(std::shared_ptr<evm_tx>& tx,
                                     const evmc::address& from,
                                     bool dry_run) -> bool;
        auto run_get_account() -> bool;
        static auto check_base_gas(std::shared_ptr<evm_tx>& tx, bool dry_run)
            -> std::pair<evmc::uint256be, bool>;
        static auto make_tx_context(std::shared_ptr<evm_tx>& tx,
                                    const evmc::address& from,
                                    bool dry_run) -> evmc_tx_context;
        static auto make_message(std::shared_ptr<evm_tx>& tx,
                                 const evmc::address& from,
                                 bool dry_run)
            -> std::pair<evmc_message, bool>;
    };
}

#endif
