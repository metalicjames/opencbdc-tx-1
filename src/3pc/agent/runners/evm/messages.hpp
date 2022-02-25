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
        evmc::uint256be m_balance;
        std::vector<uint8_t> m_code;
        std::map<evmc::bytes32, evmc::bytes32> m_storage;
        std::set<evmc::bytes32> m_modified;
        bool m_destruct{false};
    };
}

#endif
