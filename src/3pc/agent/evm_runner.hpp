// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_RUNNER_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_RUNNER_H_

#include "runner.hpp"
#include "util/serialization/util.hpp"

#include <evmc/evmc.hpp>
#include <map>

namespace cbdc::threepc::agent {
    struct evm_account {
        evmc::uint256be m_balance;
        std::vector<uint8_t> m_code;
        std::map<evmc::bytes32, evmc::bytes32> m_storage;
    };

    class host : public evmc::Host {
      public:
        host(runner::try_lock_callback_type try_lock_callback,
             evmc_tx_context tx_context);

        [[nodiscard]] auto
        account_exists(const evmc::address& addr) const noexcept -> bool final;

        [[nodiscard]] auto get_storage(const evmc::address& addr,
                                       const evmc::bytes32& key) const noexcept
            -> evmc::bytes32 final;

        auto set_storage(const evmc::address& addr,
                         const evmc::bytes32& key,
                         const evmc::bytes32& value) noexcept
            -> evmc_storage_status final;

        [[nodiscard]] auto
        get_balance(const evmc::address& addr) const noexcept
            -> evmc::uint256be final;

        [[nodiscard]] auto
        get_code_size(const evmc::address& addr) const noexcept
            -> size_t final;

        [[nodiscard]] auto
        get_code_hash(const evmc::address& addr) const noexcept
            -> evmc::bytes32 final;

        auto copy_code(const evmc::address& addr,
                       size_t code_offset,
                       uint8_t* buffer_data,
                       size_t buffer_size) const noexcept -> size_t final;

        void selfdestruct(const evmc::address& addr,
                          const evmc::address& beneficiary) noexcept final;

        auto call(const evmc_message& msg) noexcept -> evmc::result final;

        [[nodiscard]] auto get_tx_context() const noexcept
            -> evmc_tx_context final;

        [[nodiscard]] auto get_block_hash(int64_t number) const noexcept
            -> evmc::bytes32 final;

        void emit_log(
            const evmc::address& addr,
            const uint8_t* data,
            size_t data_size,
            // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
            const evmc::bytes32 topics[],
            size_t topics_count) noexcept final;

        auto access_account(const evmc::address& addr) noexcept
            -> evmc_access_status final;

        auto access_storage(const evmc::address& addr,
                            const evmc::bytes32& key) noexcept
            -> evmc_access_status final;

        auto get_state_updates() const
            -> runtime_locking_shard::state_update_type;

      private:
        runner::try_lock_callback_type m_try_lock_callback;
        mutable std::map<evmc::address, evm_account> m_accounts;
        evmc_tx_context m_tx_context;

        [[nodiscard]] auto get_account(const evmc::address& addr) const
            -> std::optional<evm_account>;
    };

    class evm_runner {
      public:
        evm_runner(std::shared_ptr<logging::log> logger,
                   runtime_locking_shard::value_type function,
                   parameter_type param,
                   runner::run_callback_type result_callback,
                   runner::try_lock_callback_type try_lock_callback);

        auto run() -> bool;
    };
}

#endif
