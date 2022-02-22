// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "evm_host.hpp"

#include "crypto/sha256.h"
#include "format.hpp"

#include <future>

namespace cbdc::threepc::agent {
    host::host(runner::try_lock_callback_type try_lock_callback,
               evmc_tx_context tx_context)
        : m_try_lock_callback(std::move(try_lock_callback)),
          m_tx_context(tx_context) {}

    auto host::get_account(const evmc::address& addr) const
        -> std::optional<evm_account> {
        auto it = m_accounts.find(addr);
        if(it != m_accounts.end()) {
            return it->second;
        }

        auto addr_key = cbdc::buffer();
        addr_key.append(&addr.bytes[0], sizeof(addr.bytes));

        auto res_prom
            = std::promise<broker::interface::try_lock_return_type>();
        auto res_fut = res_prom.get_future();

        auto ret = m_try_lock_callback(
            addr_key,
            [&](const broker::interface::try_lock_return_type& res) {
                res_prom.set_value(res);
            });

        if(!ret) {
            // TODO: error handling
            return std::nullopt;
        }

        auto res = res_fut.get();
        if(std::holds_alternative<broker::value_type>(res)) {
            auto v = std::get<broker::value_type>(res);
            auto maybe_acc = from_buffer<evm_account>(v);
            if(!maybe_acc.has_value()) {
                // TODO: error handling
                return std::nullopt;
            }
            auto& acc = maybe_acc.value();
            m_accounts[addr] = acc;
            return acc;
        }

        // TODO: error handling

        return std::nullopt;
    }

    auto host::account_exists(const evmc::address& addr) const noexcept
        -> bool {
        return get_account(addr).has_value();
    }

    auto host::get_storage(const evmc::address& addr,
                           const evmc::bytes32& key) const noexcept
        -> evmc::bytes32 {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            return {};
        }
        auto& acc = maybe_acc.value();
        auto it = acc.m_storage.find(key);
        if(it == acc.m_storage.end()) {
            return {};
        }
        return it->second;
    }

    auto host::set_storage(const evmc::address& addr,
                           const evmc::bytes32& key,
                           const evmc::bytes32& value) noexcept
        -> evmc_storage_status {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            maybe_acc = evm_account();
        }
        auto& acc = maybe_acc.value();
        auto prev_value = acc.m_storage[key];
        acc.m_storage[key] = value;
        m_accounts[addr] = acc;
        return (prev_value == value) ? EVMC_STORAGE_UNCHANGED
                                     : EVMC_STORAGE_MODIFIED;
    }

    auto host::get_balance(const evmc::address& addr) const noexcept
        -> evmc::uint256be {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            return {};
        }
        auto& acc = maybe_acc.value();
        return acc.m_balance;
    }

    auto host::get_code_size(const evmc::address& addr) const noexcept
        -> size_t {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            return {};
        }
        auto& acc = maybe_acc.value();
        return acc.m_code.size();
    }

    auto host::get_code_hash(const evmc::address& addr) const noexcept
        -> evmc::bytes32 {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            return {};
        }
        auto& acc = maybe_acc.value();
        auto sha = CSHA256();
        sha.Write(acc.m_code.data(), acc.m_code.size());
        auto ret = evmc::bytes32();
        sha.Finalize(&ret.bytes[0]);
        return ret;
    }

    auto host::copy_code(const evmc::address& addr,
                         size_t code_offset,
                         uint8_t* buffer_data,
                         size_t buffer_size) const noexcept -> size_t {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            return 0;
        }

        const auto& code = maybe_acc.value().m_code;

        if(code_offset >= code.size()) {
            return 0;
        }

        const auto n = std::min(buffer_size, code.size() - code_offset);
        if(n > 0) {
            std::copy_n(&code[code_offset], n, buffer_data);
        }
        return n;
    }

    void host::selfdestruct(const evmc::address& /* addr */,
                            const evmc::address& /* beneficiary */) noexcept {
        // TODO
    }

    auto host::call(const evmc_message& msg) noexcept -> evmc::result {
        // TODO
        return {EVMC_REVERT, msg.gas, msg.input_data, msg.input_size};
    }

    auto host::get_tx_context() const noexcept -> evmc_tx_context {
        return m_tx_context;
    }

    auto host::get_block_hash(int64_t /* number */) const noexcept
        -> evmc::bytes32 {
        // TODO: there are no blocks for this host. Ensure it's okay to always
        // return 0.
        return {};
    }

    void host::emit_log(const evmc::address& /* addr */,
                        const uint8_t* /* data */,
                        size_t /* data_size */,
                        const evmc::bytes32* /* topics[] */,
                        size_t /* topics_count */) noexcept {
        // TODO
    }

    auto host::access_account(const evmc::address& /* addr */) noexcept
        -> evmc_access_status {
        // TODO
        return EVMC_ACCESS_COLD;
    }

    auto host::access_storage(const evmc::address& /* addr */,
                              const evmc::bytes32& /* key */) noexcept
        -> evmc_access_status {
        // TODO
        return EVMC_ACCESS_COLD;
    }

    auto host::get_state_updates() const
        -> runtime_locking_shard::state_update_type {
        auto ret = runtime_locking_shard::state_update_type();
        for(auto& [addr, acc] : m_accounts) {
            auto key = make_buffer(addr);
            auto val = make_buffer(acc);
            ret[key] = val;
        }
        return ret;
    }
}
