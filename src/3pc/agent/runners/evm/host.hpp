// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_HOST_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_EVM_HOST_H_

#include "3pc/agent/runners/evm/messages.hpp"
#include "3pc/agent/runners/interface.hpp"
#include "util/serialization/util.hpp"

#include <evmc/evmc.hpp>
#include <map>
#include <set>

namespace cbdc::threepc::agent::runner {
    class evm_host : public evmc::Host {
      public:
        evm_host(std::shared_ptr<logging::log> log,
                 interface::try_lock_callback_type try_lock_callback,
                 evmc_tx_context tx_context,
                 std::shared_ptr<evmc::VM> vm,
                 evm_tx tx,
                 bool dry_run);

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

        auto should_retry() const -> bool;

        void insert_account(const evmc::address& addr, const evm_account& acc);

        void finalize(int64_t gas_left, int64_t gas_used);

        void revert();

        auto get_tx_receipt() const -> evm_tx_receipt;

      private:
        std::shared_ptr<logging::log> m_log;
        runner::interface::try_lock_callback_type m_try_lock_callback;
        mutable std::map<evmc::address,
                         std::pair<std::optional<evm_account>, bool>>
            m_accounts;
        mutable std::map<
            evmc::address,
            std::map<evmc::bytes32,
                     std::pair<std::optional<evmc::bytes32>, bool>>>
            m_account_storage;
        mutable std::map<evmc::address,
                         std::pair<std::optional<evm_account_code>, bool>>
            m_account_code;
        evmc_tx_context m_tx_context;
        std::shared_ptr<evmc::VM> m_vm;
        evm_tx m_tx;
        bool m_dry_run;

        mutable std::set<evmc::address> m_accessed_addresses;
        std::set<std::pair<evmc::address, evmc::bytes32>>
            m_accessed_storage_keys;

        mutable bool m_retry{false};

        std::map<evmc::address, std::pair<std::optional<evm_account>, bool>>
            m_init_state;

        evm_tx_receipt m_receipt;
        cbdc::buffer m_tx_id;

        [[nodiscard]] auto get_account(const evmc::address& addr,
                                       bool write) const
            -> std::optional<evm_account>;

        [[nodiscard]] auto get_account_storage(const evmc::address& addr,
                                               const evmc::bytes32& key,
                                               bool write) const
            -> std::optional<evmc::bytes32>;

        [[nodiscard]] auto get_account_code(const evmc::address& addr,
                                            bool write) const
            -> std::optional<evm_account_code>;

        void transfer(const evmc::address& from,
                      const evmc::address& to,
                      const evmc::uint256be& value);

        static auto is_precompile(const evmc::address& addr) -> bool;

        [[nodiscard]] auto get_key(const cbdc::buffer& key, bool write) const
            -> std::optional<broker::value_type>;
    };
}

#endif
