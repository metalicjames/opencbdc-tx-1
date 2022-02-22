// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "evm_runner.hpp"

#include "evm_host.hpp"

#include <evmc/loader.h>

namespace cbdc::threepc::agent {
    evm_runner::evm_runner(std::shared_ptr<logging::log> logger,
                           runtime_locking_shard::value_type function,
                           parameter_type param,
                           runner::run_callback_type result_callback,
                           runner::try_lock_callback_type try_lock_callback)
        : m_log(std::move(logger)),
          m_function(std::move(function)),
          m_param(std::move(param)),
          m_result_callback(std::move(result_callback)),
          m_try_lock_callback(std::move(try_lock_callback)) {}

    evm_runner::~evm_runner() {
        if(m_evm_thread.joinable()) {
            m_evm_thread.join();
        }
    }

    auto evm_runner::run() -> bool {
        const auto* config_string = "libexample-vm.dylib";
        auto error_code = EVMC_LOADER_UNSPECIFIED_ERROR;

        m_vm = decltype(m_vm)(
            evmc_load_and_configure(config_string, &error_code),
            &evmc_destroy);

        if(!m_vm) {
            m_log->error("Unable to load EVM implementation");
            return false;
        }

        constexpr int64_t gas = 200000;
        auto tx_ctx = evmc_tx_context();
        tx_ctx.block_number = 42;
        tx_ctx.block_timestamp = 66;
        tx_ctx.block_gas_limit = gas * 2;

        m_evm_host = std::make_unique<host>(m_try_lock_callback, tx_ctx);

        m_evm_thread = std::thread([&]() {
            const uint8_t input[] = "Hello World!";
            const evmc_uint256be value = {{1, 0}};
            const evmc_address addr = {{0, 1, 2}};

            auto msg = evmc_message();
            msg.kind = EVMC_CALL;
            msg.sender = addr;
            msg.recipient = addr;
            msg.value = value;
            msg.input_data = input;
            msg.input_size = sizeof(input);
            msg.gas = gas;
            msg.depth = 0;

            auto code = std::vector<uint8_t>(m_function.size());
            std::memcpy(code.data(), m_function.data(), m_function.size());

            auto* host_ctx = m_evm_host->to_context();
            const auto* host_intf = &evmc::Host::get_interface();
            auto result = evmc_execute(m_vm.get(),
                                       host_intf,
                                       host_ctx,
                                       EVMC_HOMESTEAD,
                                       &msg,
                                       code.data(),
                                       code.size());
            if(result.status_code != EVMC_SUCCESS) {
                // TODO: error handling
                m_log->error("Error running EVM contract");
            } else {
                auto state_updates = m_evm_host->get_state_updates();
                m_result_callback(state_updates);
            }

            evmc_release_result(&result);
        });

        return true;
    }
}
