// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "impl.hpp"

#include "format.hpp"
#include "host.hpp"
#include "math.hpp"
#include "serialization.hpp"
#include "signature.hpp"
#include "util.hpp"
#include "util/serialization/format.hpp"

#include <evmone/evmone.h>

namespace cbdc::threepc::agent::runner {
    evm_runner::evm_runner(std::shared_ptr<logging::log> logger,
                           const cbdc::threepc::config& cfg,
                           runtime_locking_shard::value_type function,
                           parameter_type param,
                           bool dry_run,
                           run_callback_type result_callback,
                           try_lock_callback_type try_lock_callback)
        : interface(std::move(logger),
                    cfg,
                    std::move(function),
                    std::move(param),
                    dry_run,
                    std::move(result_callback),
                    std::move(try_lock_callback)) {}

    evm_runner::~evm_runner() {
        if(m_evm_thread.joinable()) {
            m_evm_thread.join();
        }
    }

    auto evm_runner::run() -> bool {
        if(m_function.size() != 1) {
            m_log->error("EVM runner expects 1 byte in m_function, got ",
                         m_function.size());
            m_result_callback(error_code::function_load);
            return true;
        }

        static constexpr uint8_t invalid_function = 255;
        uint8_t f = invalid_function;
        std::memcpy(&f, m_function.data(), sizeof(uint8_t));
        if(f > static_cast<uint8_t>(
               evm_runner_function::get_transaction_receipt)) {
            m_log->error("Unknown EVM runner function ", f);
            m_result_callback(error_code::function_load);
            return true;
        }

        switch(evm_runner_function(f)) {
            case evm_runner_function::execute_transaction:
                return run_execute_real_transaction();
            case evm_runner_function::read_account:
                return run_get_account();
            case evm_runner_function::dryrun_transaction:
                return run_execute_dryrun_transaction();
            case evm_runner_function::read_account_code:
                return run_get_account_code();
            case evm_runner_function::get_transaction:
                return run_get_transaction();
            case evm_runner_function::get_transaction_receipt:
                return run_get_transaction_receipt();
        }

        return false;
    }

    auto evm_runner::run_get_account() -> bool {
        m_try_lock_callback(
            m_param,
            broker::lock_type::read,
            [this](const broker::interface::try_lock_return_type& res) {
                if(!std::holds_alternative<broker::value_type>(res)) {
                    m_log->error("Failed to read account from shards");
                    m_result_callback(error_code::function_load);
                    return;
                }
                auto v = std::get<broker::value_type>(res);
                auto ret = runtime_locking_shard::state_update_type();
                ret[m_param] = v;
                m_result_callback(ret);
            });

        return true;
    }

    auto evm_runner::run_get_transaction_receipt() -> bool {
        m_try_lock_callback(
            m_param,
            broker::lock_type::read,
            [this](const broker::interface::try_lock_return_type& res) {
                if(!std::holds_alternative<broker::value_type>(res)) {
                    m_log->error(
                        "Failed to read transaction receipt from shards");
                    m_result_callback(error_code::function_load);
                    return;
                }
                auto v = std::get<broker::value_type>(res);
                auto ret = runtime_locking_shard::state_update_type();
                ret[m_param] = v;
                m_result_callback(ret);
            });

        return true;
    }

    auto evm_runner::run_get_transaction() -> bool {
        m_try_lock_callback(
            m_param,
            broker::lock_type::read,
            [this](const broker::interface::try_lock_return_type& res) {
                if(!std::holds_alternative<broker::value_type>(res)) {
                    m_log->error(
                        "Failed to read transaction receipt from shards");
                    m_result_callback(error_code::function_load);
                    return;
                }
                auto v = std::get<broker::value_type>(res);
                auto ret = runtime_locking_shard::state_update_type();

                m_log->trace("Read transaction receipt: ", v.to_hex());

                auto maybe_receipt = cbdc::from_buffer<evm_tx_receipt>(v);
                if(!maybe_receipt.has_value()) {
                    m_log->error("Failed to deserialize transaction receipt");
                    m_result_callback(error_code::function_load);
                    return;
                }
                ret[m_param] = make_buffer(maybe_receipt.value().m_tx);
                m_result_callback(ret);
            });

        return true;
    }

    auto evm_runner::run_get_account_code() -> bool {
        auto addr = evmc::address();
        std::memcpy(addr.bytes, m_param.data(), m_param.size());
        auto key = make_buffer(code_key{addr});
        m_try_lock_callback(
            key,
            broker::lock_type::read,
            [this](const broker::interface::try_lock_return_type& res) {
                if(!std::holds_alternative<broker::value_type>(res)) {
                    m_log->error("Failed to read account from shards");
                    m_result_callback(error_code::function_load);
                    return;
                }
                auto v = std::get<broker::value_type>(res);
                auto ret = runtime_locking_shard::state_update_type();
                ret[m_param] = v;
                m_result_callback(ret);
            });

        return true;
    }

    auto evm_runner::run_execute_real_transaction() -> bool {
        auto maybe_tx = cbdc::from_buffer<evm_tx>(m_param);
        if(!maybe_tx.has_value()) {
            m_log->error("Unable to deserialize transaction");
            m_result_callback(error_code::function_load);
            return true;
        }
        auto tx = std::make_shared<evm_tx>(std::move(maybe_tx.value()));

        auto maybe_from = check_signature(tx, m_secp);
        if(!maybe_from.has_value()) {
            m_log->error("Transaction signature is invalid");
            m_result_callback(error_code::exec_error);
            return true;
        }
        auto from = maybe_from.value();
        return run_execute_transaction(tx, from, false);
    }

    auto evm_runner::run_execute_dryrun_transaction() -> bool {
        auto maybe_tx = cbdc::from_buffer<evm_dryrun_tx>(m_param);
        if(!maybe_tx.has_value()) {
            m_log->error("Unable to deserialize transaction");
            m_result_callback(error_code::function_load);
            return true;
        }
        auto dryrun_tx = maybe_tx.value();
        auto tx = std::make_shared<evm_tx>(std::move(dryrun_tx.m_tx));
        return run_execute_transaction(tx, dryrun_tx.m_from, true);
    }

    auto evm_runner::check_base_gas(std::shared_ptr<evm_tx>& tx, bool dry_run)
        -> std::pair<evmc::uint256be, bool> {
        constexpr auto base_gas = evmc::uint256be(21000);
        constexpr auto creation_gas = evmc::uint256be(32000);

        auto min_gas = base_gas;
        if(!tx->m_to.has_value()) {
            min_gas = min_gas + creation_gas;
        }

        return std::make_pair(min_gas,
                              !(tx->m_gas_limit < min_gas && !dry_run));
    }

    auto evm_runner::make_message(std::shared_ptr<evm_tx>& tx,
                                  const evmc::address& from,
                                  bool dry_run)
        -> std::pair<evmc_message, bool> {
        auto msg = evmc_message();

        auto [min_gas, enough_gas] = check_base_gas(tx, dry_run);
        if(!enough_gas) {
            return std::make_pair(msg, false);
        }

        // Note that input_data is a const reference to the input buffer. The
        // buffer itself must remain in scope while msg is being used. Wrap tx
        // in a shared_ptr and provide it to the thread using msg.
        msg.input_data = tx->m_input.data();
        msg.input_size = tx->m_input.size();
        msg.depth = 0;

        // Determine transaction type
        if(!tx->m_to.has_value()) {
            // Create contract transaction
            msg.kind = EVMC_CREATE;
        } else {
            // Send transaction
            msg.kind = EVMC_CALL;
            msg.recipient = tx->m_to.value();
        }

        msg.sender = from;
        msg.value = tx->m_value;
        if(dry_run) {
            msg.gas = std::numeric_limits<int64_t>::max();
        } else {
            msg.gas
                = static_cast<int64_t>(to_uint64(tx->m_gas_limit - min_gas));
        }
        return std::make_pair(msg, true);
    }

    auto evm_runner::make_tx_context(std::shared_ptr<evm_tx>& tx,
                                     const evmc::address& from,
                                     bool dry_run) -> evmc_tx_context {
        auto tx_ctx = evmc_tx_context();
        // TODO: consider setting block height to the TX ticket number
        tx_ctx.block_number = 1;
        auto now = std::chrono::high_resolution_clock::now();
        auto timestamp
            = std::chrono::time_point_cast<std::chrono::seconds>(now);
        tx_ctx.block_timestamp = timestamp.time_since_epoch().count();
        if(!dry_run) {
            tx_ctx.tx_origin = from;
            tx_ctx.tx_gas_price = tx->m_gas_price;
            tx_ctx.block_gas_limit
                = static_cast<int64_t>(to_uint64(tx->m_gas_limit));
        } else {
            tx_ctx.block_gas_limit = std::numeric_limits<int64_t>::max();
        }
        return tx_ctx;
    }

    auto evm_runner::run_execute_transaction(std::shared_ptr<evm_tx>& tx,
                                             const evmc::address& from,
                                             bool dry_run) -> bool {
        auto tx_ctx = make_tx_context(tx, from, dry_run);

        m_vm = std::make_shared<evmc::VM>(evmc_create_evmone());
        if(!(*m_vm)) {
            m_log->error("Unable to load EVM implementation");
            return false;
        }

        auto host = std::make_shared<evm_host>(m_log,
                                               m_try_lock_callback,
                                               tx_ctx,
                                               m_vm,
                                               *tx,
                                               dry_run);

        auto [msg, enough_gas] = make_message(tx, from, dry_run);
        if(!enough_gas) {
            m_log->trace("TX does not have enough base gas");
            m_result_callback(error_code::exec_error);
            return true;
        }

        if(!dry_run) {
            m_log->trace("Reading from account [", to_hex(from), "]");
            auto addr_key = cbdc::make_buffer(from);
            m_try_lock_callback(
                addr_key,
                broker::lock_type::write,
                [this, m{std::move(msg)}, host, tx](
                    const broker::interface::try_lock_return_type& res) {
                    if(!std::holds_alternative<broker::value_type>(res)) {
                        m_log->error("Failed to read account from shards");
                        m_result_callback(error_code::function_load);
                        return;
                    }
                    auto v = std::get<broker::value_type>(res);
                    auto from_acc = evm_account();
                    if(v.size() > 0) {
                        auto maybe_from_acc
                            = cbdc::from_buffer<evm_account>(v);
                        if(maybe_from_acc.has_value()) {
                            from_acc = maybe_from_acc.value();
                        }
                    }

                    if(from_acc.m_nonce + evmc::uint256be(1) != tx->m_nonce) {
                        m_log->trace(
                            "TX has incorrect nonce for from account");
                        m_result_callback(error_code::exec_error);
                        return;
                    }

                    // TODO: Priority fees for V2 transactions
                    auto total_gas_cost = tx->m_gas_limit * tx->m_gas_price;
                    auto required_funds = tx->m_value + total_gas_cost;

                    if(from_acc.m_balance < required_funds) {
                        m_log->trace(
                            "From account has insufficient funds to cover gas "
                            "and tx value");
                        m_result_callback(error_code::exec_error);
                        return;
                    }

                    // Deduct gas
                    from_acc.m_balance = from_acc.m_balance - total_gas_cost;
                    // Increment nonce
                    from_acc.m_nonce = from_acc.m_nonce + evmc::uint256be(1);
                    host->insert_account(m.sender, from_acc);

                    const auto txid_key = make_buffer(tx_id(tx));
                    // Lock TXID key to store receipt later
                    m_try_lock_callback(
                        txid_key,
                        broker::lock_type::write,
                        [this, m, host, tx](
                            const broker::interface::try_lock_return_type&) {
                            // Capture the tx as a shared_ptr here so the
                            // memory backing msg.input_data remains in scope.
                            m_evm_thread = std::thread([this, m, host, tx]() {
                                exec(m, host);
                            });
                        });
                });
        } else {
            // Capture the tx as a shared_ptr here so the memory backing
            // msg.input_data remains in scope.
            m_evm_thread = std::thread([this, m{std::move(msg)}, host, tx]() {
                exec(m, host);
            });
        }

        return true;
    }

    void evm_runner::exec(const evmc_message& msg,
                          const std::shared_ptr<evm_host>& host) {
        m_log->trace(this, "Started evm_runner exec");
        auto result = host->call(msg);
        if(result.status_code < 0) {
            m_log->error("Internal error running EVM contract",
                         evmc::to_string(result.status_code));
            m_result_callback(error_code::internal_error);
        } else if(host->should_retry()) {
            m_log->trace("Contract was wounded");
            m_result_callback(error_code::wounded);
        } else {
            if(result.status_code == EVMC_REVERT) {
                m_log->trace("Contract reverted");
                host->revert();
            }

            m_log->trace("Result status: ", result.status_code);

            auto gas_used
                = static_cast<int64_t>(m_gas_limit) - result.gas_left;
            host->finalize(result.gas_left, gas_used);
            auto state_updates = host->get_state_updates();
            m_result_callback(state_updates);
            auto out_buf = cbdc::buffer();
            out_buf.append(result.output_data, result.output_size);
            m_log->trace("EVM output data:", out_buf.to_hex());
        }
    }
}
