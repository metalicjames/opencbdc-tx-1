// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "format.hpp"

#include "util/serialization/format.hpp"

namespace cbdc {
    auto operator<<(serializer& ser,
                    const threepc::agent::runner::evm_account& acc)
        -> serializer& {
        return ser << acc.m_balance << acc.m_code << acc.m_storage;
    }

    auto operator>>(serializer& deser,
                    threepc::agent::runner::evm_account& acc) -> serializer& {
        return deser >> acc.m_balance >> acc.m_code >> acc.m_storage;
    }

    auto operator<<(serializer& ser, const evmc::address& addr)
        -> serializer& {
        ser.write(addr.bytes, sizeof(addr.bytes));
        return ser;
    }

    auto operator>>(serializer& deser, evmc::address& addr) -> serializer& {
        deser.read(addr.bytes, sizeof(addr.bytes));
        return deser;
    }

    auto operator<<(serializer& ser, const evmc::bytes32& b) -> serializer& {
        ser.write(b.bytes, sizeof(b.bytes));
        return ser;
    }

    auto operator>>(serializer& deser, evmc::bytes32& b) -> serializer& {
        deser.read(b.bytes, sizeof(b.bytes));
        return deser;
    }
}
