// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_UTIL_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_UTIL_H_

#include "messages.hpp"
#include "util/common/buffer.hpp"

#include <evmc/evmc.hpp>
#include <evmc/hex.hpp>

namespace cbdc::threepc::agent::runner {
    auto to_uint64(const evmc::uint256be& v) -> uint64_t;

    template<typename T>
    auto to_hex(const T& v) -> std::string {
        return evmc::hex(evmc::bytes(v.bytes, sizeof(v.bytes)));
    }

    auto tx_id(const evm_tx& tx) -> cbdc::buffer;
}

#endif
