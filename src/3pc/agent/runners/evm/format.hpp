// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_FORMAT_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_EVM_FORMAT_H_

#include "messages.hpp"
#include "util/serialization/serializer.hpp"

namespace cbdc {
    auto operator<<(serializer& ser,
                    const threepc::agent::runner::evm_account& acc)
        -> serializer&;
    auto operator>>(serializer& deser,
                    threepc::agent::runner::evm_account& acc) -> serializer&;

    auto operator<<(serializer& ser, const evmc::address& addr) -> serializer&;
    auto operator>>(serializer& deser, evmc::address& addr) -> serializer&;

    auto operator<<(serializer& ser, const evmc::bytes32& b) -> serializer&;
    auto operator>>(serializer& deser, evmc::bytes32& b) -> serializer&;

    auto operator<<(serializer& ser, const threepc::agent::runner::evm_tx& tx)
        -> serializer&;
    auto operator>>(serializer& deser, threepc::agent::runner::evm_tx& tx)
        -> serializer&;

    auto operator<<(serializer& ser, const threepc::agent::runner::evm_sig& s)
        -> serializer&;
    auto operator>>(serializer& deser, threepc::agent::runner::evm_sig& s)
        -> serializer&;

    auto operator<<(serializer& ser,
                    const threepc::agent::runner::evm_access_tuple& at)
        -> serializer&;
    auto operator>>(serializer& deser,
                    threepc::agent::runner::evm_access_tuple& at)
        -> serializer&;

    auto operator<<(serializer& ser, const threepc::agent::runner::evm_log& l)
        -> serializer&;
    auto operator>>(serializer& deser, threepc::agent::runner::evm_log& l)
        -> serializer&;

    auto operator<<(serializer& ser,
                    const threepc::agent::runner::evm_tx_receipt& r)
        -> serializer&;
    auto operator>>(serializer& deser,
                    threepc::agent::runner::evm_tx_receipt& r) -> serializer&;
}

#endif
