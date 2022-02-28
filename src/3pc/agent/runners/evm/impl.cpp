// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "impl.hpp"

#include "format.hpp"
#include "host.hpp"

#include <evmc/loader.h>

namespace cbdc::threepc::agent::runner {
    evm_runner::evm_runner(std::shared_ptr<logging::log> logger,
                           runtime_locking_shard::value_type function,
                           parameter_type param,
                           run_callback_type result_callback,
                           try_lock_callback_type try_lock_callback)
        : interface(std::move(logger),
                    std::move(function),
                    std::move(param),
                    result_callback,
                    try_lock_callback) {}

    evm_runner::~evm_runner() {
        if(m_evm_thread.joinable()) {
            m_evm_thread.join();
        }
    }

    auto evm_runner::run() -> bool {
        /*const auto* config_string = "libexample-vm.dylib";
        auto load_error = EVMC_LOADER_UNSPECIFIED_ERROR;

        m_vm = std::make_shared<evmc::VM>(
            evmc_load_and_configure(config_string, &load_error));
        if(!(*m_vm)) {
            m_log->error("Unable to load EVM implementation");
            return false;
        }*/

        auto maybe_from_acc = from_buffer<evm_account>(m_function);
        if(!maybe_from_acc.has_value()) {
            m_log->error("Unable to deserialize account");
            return false;
        }
        auto& from_acc = maybe_from_acc.value();

        auto maybe_tx = from_buffer<evm_tx>(m_param);
        if(!maybe_tx.has_value()) {
            m_log->error("Unable to deserialize transaction");
            return false;
        }
        auto& tx = maybe_tx.value();

        auto tx_nonce = evmc::load64be(tx.m_nonce.bytes);
        auto acc_nonce = evmc::load64be(from_acc.m_nonce.bytes);

        if(acc_nonce + 1 != tx_nonce) {
            m_log->trace("TX has incorrect nonce for from account");
            m_result_callback(error_code::exec_error);
            return true;
        }

        auto gas_limit = evmc::load64be(tx.m_gas_limit.bytes);
        auto gas_price = evmc::load64be(tx.m_gas_price.bytes);
        auto value = evmc::load64be(tx.m_value.bytes);
        auto balance = evmc::load64be(from_acc.m_balance.bytes);

        auto total_gas_cost = gas_limit * gas_price;

        auto required_funds = value + total_gas_cost;
        if(balance < required_funds) {
            m_log->trace("From account has insufficient funds to cover gas "
                         "and tx value");
            m_result_callback(error_code::exec_error);
            return true;
        }

        auto tx_ctx = evmc_tx_context();
        // TODO: consider setting block height to the TX ticket number
        tx_ctx.block_number = 1;
        auto now = std::chrono::high_resolution_clock::now();
        auto timestamp
            = std::chrono::time_point_cast<std::chrono::seconds>(now);
        tx_ctx.block_timestamp = timestamp.time_since_epoch().count();
        tx_ctx.block_gas_limit = static_cast<int64_t>(gas_limit);
        tx_ctx.tx_origin = tx.m_from;
        tx_ctx.tx_gas_price = tx.m_gas_price;

        auto host = std::make_shared<evm_host>(m_log,
                                               m_try_lock_callback,
                                               tx_ctx,
                                               m_vm);

        // Deduct gas
        auto new_bal = balance - total_gas_cost;
        from_acc.m_balance = evmc::uint256be(new_bal);
        // Increment nonce
        auto new_nonce = acc_nonce + 1;
        from_acc.m_nonce = evmc::uint256be(new_nonce);
        host->insert_account(tx.m_from, from_acc);

        auto msg = evmc_message();
        msg.sender = tx.m_from;
        msg.value = tx.m_value;
        // TODO: make sure tx.m_input remains in scope
        msg.input_data = tx.m_input.data();
        msg.input_size = tx.m_input.size();
        msg.gas = static_cast<int64_t>(gas_limit);
        msg.depth = 0;

        // Determine transaction type
        if(!tx.m_to.has_value()) {
            // Create contract transaction
            msg.kind = EVMC_CREATE;
        } else {
            // Send transaction
            msg.kind = EVMC_CALL;
            msg.recipient = tx.m_to.value();
        }

        m_evm_thread = std::thread([this, msg, host]() {
            exec(msg, host);
        });

        return true;
    }

    void evm_runner::exec(const evmc_message& msg,
                          std::shared_ptr<evm_host> host) {
        auto result = host->call(msg);
        // TODO: gas refund to origin account
        if(result.status_code != EVMC_SUCCESS) {
            m_log->error("Error running EVM contract",
                         evmc::to_string(result.status_code));
            m_result_callback(error_code::exec_error);
        } else if(host->should_retry()) {
            m_result_callback(error_code::wounded);
        } else {
            auto state_updates = host->get_state_updates();
            m_result_callback(state_updates);
        }
    }
}
