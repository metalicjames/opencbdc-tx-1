// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_MESSAGES_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_MESSAGES_H_

#include "util/common/hash.hpp"

#include <evmc/evmc.hpp>
#include <map>
#include <optional>
#include <set>
#include <vector>

namespace cbdc::threepc::agent::runner {
    // EVM Chain ID for OpenCBDC
    static constexpr uint64_t opencbdc_chain_id = 0xcbdc;

    struct evm_account {
        evmc::uint256be m_balance{};
        evmc::uint256be m_nonce{};

        std::set<evmc::bytes32> m_modified{};
        bool m_destruct{false};
    };

    using evm_account_code = std::vector<uint8_t>;

    struct evm_sig {
        evmc::uint256be m_r;
        evmc::uint256be m_s;
        evmc::uint256be m_v;
    };

    struct evm_access_tuple {
        evmc::address m_address{};
        std::vector<evmc::bytes32> m_storage_keys{};
        auto operator==(const evm_access_tuple& rhs) const -> bool {
            return m_address == rhs.m_address
                && m_storage_keys == rhs.m_storage_keys;
        };
    };

    using evm_access_list = std::vector<evm_access_tuple>;

    enum class evm_tx_type : uint8_t {
        legacy = 0,
        access_list = 1,
        dynamic_fee = 2
    };

    struct evm_tx {
        evm_tx_type m_type{};
        evmc::address m_from{};
        std::optional<evmc::address> m_to{};
        evmc::uint256be m_value{};
        evmc::uint256be m_nonce{};
        evmc::uint256be m_gas_price{};
        evmc::uint256be m_gas_limit{};
        evmc::uint256be m_gas_tip_cap{};
        evmc::uint256be m_gas_fee_cap{};
        std::vector<uint8_t> m_input{};
        evm_access_list m_access_list{};
        evm_sig m_sig;
    };

    struct evm_log {
        evmc::address m_addr{};
        std::vector<uint8_t> m_data{};
        std::vector<evmc::bytes32> m_topics{};
    };

    struct evm_tx_receipt {
        evm_tx m_tx;
        std::optional<evmc::address> m_create_address;
        evmc::uint256be m_gas_used{};
        std::vector<evm_log> m_logs{};
        std::vector<uint8_t> m_output_data{};
    };

    // TODO: evm namespace
    struct code_key {
        evmc::address m_addr;
    };

    struct storage_key {
        evmc::address m_addr;
        evmc::bytes32 m_key;
    };
}

#endif
