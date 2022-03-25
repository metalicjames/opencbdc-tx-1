// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "host.hpp"

#include "address.hpp"
#include "crypto/sha256.h"
#include "format.hpp"
#include "hash.hpp"
#include "rlp.hpp"
#include "util.hpp"

#include <cassert>
#include <evmc/hex.hpp>
#include <future>

namespace cbdc::threepc::agent::runner {
    evm_host::evm_host(std::shared_ptr<logging::log> log,
                       interface::try_lock_callback_type try_lock_callback,
                       evmc_tx_context tx_context,
                       std::shared_ptr<evmc::VM> vm,
                       evm_tx tx,
                       bool dry_run)
        : m_log(std::move(log)),
          m_try_lock_callback(std::move(try_lock_callback)),
          m_tx_context(tx_context),
          m_vm(std::move(vm)),
          m_tx(std::move(tx)),
          m_dry_run(dry_run) {
        m_receipt.m_tx = m_tx;
    }

    auto evm_host::get_account(const evmc::address& addr) const
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
            m_log->trace("Failed to make try_lock request, retrying");
            m_retry = true;
            return std::nullopt;
        }

        auto res = res_fut.get();
        if(std::holds_alternative<broker::value_type>(res)) {
            m_accessed_addresses.insert(addr);
            auto v = std::get<broker::value_type>(res);
            if(v.size() == 0) {
                m_accounts[addr] = std::nullopt;
                return std::nullopt;
            }
            auto maybe_acc = from_buffer<evm_account>(v);
            assert(maybe_acc.has_value());
            auto& acc = maybe_acc.value();
            m_accounts[addr] = acc;
            return acc;
        }

        m_log->trace("Try_lock request returned an error, retrying");

        m_retry = true;

        return std::nullopt;
    }

    auto evm_host::account_exists(const evmc::address& addr) const noexcept
        -> bool {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            return false;
        }
        auto& acc = maybe_acc.value();
        return !acc.m_destruct;
    }

    auto evm_host::get_storage(const evmc::address& addr,
                               const evmc::bytes32& key) const noexcept
        -> evmc::bytes32 {
        m_log->trace("EVM get_storage addr:",
                     to_hex(addr),
                     "key:",
                     to_hex(key));
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

    auto evm_host::set_storage(const evmc::address& addr,
                               const evmc::bytes32& key,
                               const evmc::bytes32& value) noexcept
        -> evmc_storage_status {
        m_log->trace("EVM set_storage addr:",
                     to_hex(addr),
                     "key:",
                     to_hex(key),
                     "val:",
                     to_hex(value));
        auto ret_val = std::optional<evmc_storage_status>();
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            maybe_acc = evm_account();
            ret_val = EVMC_STORAGE_ADDED;
            maybe_acc.value().m_modified.insert(key);
        }
        auto& acc = maybe_acc.value();
        auto prev_value = acc.m_storage[key];
        auto modified = acc.m_modified.find(key) != acc.m_modified.end();
        if(!ret_val.has_value()) {
            if(prev_value == value) {
                ret_val = EVMC_STORAGE_UNCHANGED;
            } else if(evmc::is_zero(value) && !modified) {
                ret_val = EVMC_STORAGE_DELETED;
            } else if(modified) {
                ret_val = EVMC_STORAGE_MODIFIED_AGAIN;
            } else {
                ret_val = EVMC_STORAGE_MODIFIED;
                acc.m_modified.insert(key);
            }
        }
        acc.m_storage[key] = value;
        m_accounts[addr] = acc;
        assert(ret_val.has_value());
        return ret_val.value();
    }

    auto evm_host::get_balance(const evmc::address& addr) const noexcept
        -> evmc::uint256be {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            return {};
        }
        auto& acc = maybe_acc.value();
        return acc.m_balance;
    }

    auto evm_host::get_code_size(const evmc::address& addr) const noexcept
        -> size_t {
        auto maybe_acc = get_account(addr);
        if(!maybe_acc.has_value()) {
            return {};
        }
        auto& acc = maybe_acc.value();
        return acc.m_code.size();
    }

    auto evm_host::get_code_hash(const evmc::address& addr) const noexcept
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

    auto evm_host::copy_code(const evmc::address& addr,
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

    void evm_host::selfdestruct(const evmc::address& addr,
                                const evmc::address& beneficiary) noexcept {
        transfer(addr, beneficiary, evmc::uint256be{});
    }

    auto evm_host::call(const evmc_message& msg) noexcept -> evmc::result {
        if(msg.kind == EVMC_CREATE2 || msg.kind == EVMC_CREATE) {
            auto maybe_sender_acc = get_account(msg.sender);
            assert(maybe_sender_acc.has_value());
            auto& sender_acc = maybe_sender_acc.value();

            auto new_addr = evmc::address();
            if(msg.kind == EVMC_CREATE) {
                new_addr = contract_address(msg.sender, sender_acc.m_nonce);
            } else {
                auto bytecode_hash
                    = cbdc::keccak_data(msg.input_data, msg.input_size);
                new_addr = contract_address2(msg.sender,
                                             msg.create2_salt,
                                             bytecode_hash);
            }

            // Transfer endowment to deployed contract account
            if(!evmc::is_zero(msg.value)) {
                transfer(msg.sender, new_addr, msg.value);
            }

            if(msg.depth == 0) {
                m_receipt.m_create_address = new_addr;
            }

            auto call_msg = evmc_message();
            call_msg.depth = msg.depth;
            call_msg.sender = msg.sender;
            call_msg.value = msg.value;
            call_msg.recipient = new_addr;
            call_msg.kind = EVMC_CALL;
            // TODO: do we need to deduct some gas for contract creation here?
            call_msg.gas = msg.gas;

            auto res = m_vm->execute(*this,
                                     EVMC_LATEST_STABLE_REVISION,
                                     call_msg,
                                     msg.input_data,
                                     msg.input_size);

            if(res.status_code == EVMC_SUCCESS) {
                auto maybe_acc = get_account(new_addr);
                if(!maybe_acc.has_value()) {
                    maybe_acc = evm_account();
                }
                auto& acc = maybe_acc.value();
                acc.m_code.resize(res.output_size);
                std::memcpy(acc.m_code.data(),
                            res.output_data,
                            res.output_size);
                m_accounts[new_addr] = acc;
            }

            return res;
        }

        // Transfer message value from sender account to recipient
        if(!evmc::is_zero(msg.value) && msg.kind == EVMC_CALL) {
            // TODO: do DELETEGATECALL and CALLCODE transfer value as well?
            transfer(msg.sender, msg.recipient, msg.value);
        }

        auto code_addr
            = msg.kind == EVMC_DELEGATECALL || msg.kind == EVMC_CALLCODE
                ? msg.code_address
                : msg.recipient;

        auto code_size = get_code_size(code_addr);
        if(code_size == 0) {
            // TODO: deduct simple send fixed gas amount
            auto res = evmc::make_result(evmc_status_code::EVMC_SUCCESS,
                                         msg.gas,
                                         nullptr,
                                         0);
            return evmc::result(res);
        }

        auto code_buf = std::vector<uint8_t>(code_size);
        [[maybe_unused]] auto n
            = copy_code(code_addr, 0, code_buf.data(), code_buf.size());
        assert(n == code_size);

        auto res = m_vm->execute(*this,
                                 EVMC_LATEST_STABLE_REVISION,
                                 msg,
                                 code_buf.data(),
                                 code_buf.size());

        if(msg.depth == 0) {
            m_receipt.m_output_data.resize(res.output_size);
            std::memcpy(m_receipt.m_output_data.data(),
                        res.output_data,
                        res.output_size);
        }

        return res;
    }

    auto evm_host::get_tx_context() const noexcept -> evmc_tx_context {
        return m_tx_context;
    }

    auto evm_host::get_block_hash(int64_t /* number */) const noexcept
        -> evmc::bytes32 {
        // TODO: there are no blocks for this host. Ensure it's okay to always
        // return 0.
        return {};
    }

    void evm_host::emit_log(
        const evmc::address& addr,
        const uint8_t* data,
        size_t data_size,
        // NOLINTNEXTLINE(cppcoreguidelines-avoid-c-arrays,modernize-avoid-c-arrays)
        const evmc::bytes32 topics[],
        size_t topics_count) noexcept {
        auto l = evm_log();
        l.m_addr = addr;
        l.m_data.resize(data_size);
        std::memcpy(l.m_data.data(), data, data_size);
        for(size_t i = 0; i < topics_count; i++) {
            // NOLINTNEXTLINE(cppcoreguidelines-pro-bounds-pointer-arithmetic)
            l.m_topics.push_back(topics[i]);
        }
        m_receipt.m_logs.push_back(l);
    }

    auto evm_host::access_account(const evmc::address& addr) noexcept
        -> evmc_access_status {
        if(m_accessed_addresses.find(addr) != m_accessed_addresses.end()) {
            return EVMC_ACCESS_WARM;
        }
        m_accessed_addresses.insert(addr);
        return EVMC_ACCESS_COLD;
    }

    auto evm_host::access_storage(const evmc::address& addr,
                                  const evmc::bytes32& key) noexcept
        -> evmc_access_status {
        auto elem = std::make_pair(addr, key);
        if(m_accessed_storage_keys.find(elem)
           != m_accessed_storage_keys.end()) {
            return EVMC_ACCESS_WARM;
        }
        m_accessed_storage_keys.insert(elem);
        return EVMC_ACCESS_COLD;
    }

    auto evm_host::get_state_updates() const
        -> runtime_locking_shard::state_update_type {
        auto ret = runtime_locking_shard::state_update_type();
        for(auto& [addr, acc] : m_accounts) {
            if(!acc.has_value()) {
                continue;
            }
            auto key = make_buffer(addr);
            auto val = cbdc::buffer();
            if(!acc->m_destruct) {
                val = make_buffer(*acc);
            }
            ret[key] = val;
        }
        auto tid = tx_id(m_tx);
        auto r = make_buffer(m_receipt);
        ret[tid] = r;
        return ret;
    }

    auto evm_host::should_retry() const -> bool {
        return m_retry;
    }

    void evm_host::insert_account(const evmc::address& addr,
                                  const evm_account& acc) {
        m_accounts.insert({addr, acc});
        m_accessed_addresses.insert(addr);
        m_init_state = m_accounts;
    }

    void evm_host::transfer(const evmc::address& from,
                            const evmc::address& to,
                            const evmc::uint256be& value) {
        auto maybe_acc = get_account(from);
        assert(maybe_acc.has_value());
        auto& acc = maybe_acc.value();
        // TODO: 256-bit integer precision
        auto acc_bal = to_uint64(acc.m_balance);
        auto val = uint64_t{};
        if(evmc::is_zero(value)) {
            // Special case: destruct the from account if we're transfering the
            // entire account balance
            val = acc_bal;
            acc.m_destruct = true;
        } else {
            val = to_uint64(value);
        }
        auto new_bal = acc_bal - val;
        acc.m_balance = evmc::uint256be(new_bal);
        m_accounts[from] = acc;

        auto maybe_to_acc = get_account(to);
        if(!maybe_to_acc.has_value()) {
            // Create the to account if it doesn't exist
            maybe_to_acc = evm_account();
        }
        auto& to_acc = maybe_to_acc.value();
        auto to_acc_bal = to_uint64(to_acc.m_balance);
        auto new_to_acc_bal = to_acc_bal + val;
        to_acc.m_balance = evmc::uint256be(new_to_acc_bal);
        m_accounts[to] = to_acc;
    }

    void evm_host::finalize(int64_t gas_left, int64_t gas_used) {
        if(!m_dry_run) {
            auto maybe_acc = get_account(m_tx_context.tx_origin);
            assert(maybe_acc.has_value());
            auto& acc = maybe_acc.value();
            auto acc_bal = to_uint64(acc.m_balance);
            auto new_bal = acc_bal + static_cast<uint64_t>(gas_left);
            acc.m_balance = evmc::uint256be(new_bal);
            m_accounts[m_tx_context.tx_origin] = acc;
        }
        m_receipt.m_gas_used
            = evmc::uint256be(static_cast<uint64_t>(gas_used));
    }

    void evm_host::revert() {
        m_accounts = m_init_state;
    }

    auto evm_host::get_tx_receipt() const -> evm_tx_receipt {
        return m_receipt;
    }
}
