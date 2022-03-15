// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_MESSAGES_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_MESSAGES_H_

#include <evmc/evmc.hpp>
#include <map>
#include <set>
#include <vector>

namespace cbdc::threepc::agent::runner {
    struct evm_account {
        evmc::uint256be m_balance{};
        std::vector<uint8_t> m_code;
        std::map<evmc::bytes32, evmc::bytes32> m_storage;
        evmc::uint256be m_nonce{};
        std::set<evmc::bytes32> m_modified;
        bool m_destruct{false};
    };

    struct evm_tx {
        evmc::address m_from{};
        std::optional<evmc::address> m_to{};
        evmc::uint256be m_value{};
        evmc::uint256be m_nonce{};
        evmc::uint256be m_gas_price{};
        evmc::uint256be m_gas_limit{};
        std::vector<uint8_t> m_input{};
        // TODO: add signatures
    };

    struct evm_log {
        evmc::address m_addr{};
        std::vector<uint8_t> m_data{};
        std::vector<evmc::bytes32> m_topics{};
    };

    struct evm_tx_receipt {
        evmc::address m_from{};
        std::optional<evmc::address> m_to{};
        evmc::uint256be m_gas_used{};
        std::vector<evm_log> m_logs{};
        std::vector<uint8_t> m_output_data{};
    };
}

#endif
