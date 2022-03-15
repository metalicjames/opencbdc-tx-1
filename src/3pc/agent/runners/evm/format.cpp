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
        return ser << acc.m_balance << acc.m_code << acc.m_storage
                   << acc.m_nonce;
    }

    auto operator>>(serializer& deser,
                    threepc::agent::runner::evm_account& acc) -> serializer& {
        return deser >> acc.m_balance >> acc.m_code >> acc.m_storage
            >> acc.m_nonce;
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

    auto operator<<(serializer& ser, const threepc::agent::runner::evm_tx& tx)
        -> serializer& {
        return ser << tx.m_from << tx.m_to << tx.m_value << tx.m_nonce
                   << tx.m_gas_price << tx.m_gas_limit << tx.m_input;
    }

    auto operator>>(serializer& deser, threepc::agent::runner::evm_tx& tx)
        -> serializer& {
        return deser >> tx.m_from >> tx.m_to >> tx.m_value >> tx.m_nonce
            >> tx.m_gas_price >> tx.m_gas_limit >> tx.m_input;
    }

    auto operator<<(serializer& ser, const threepc::agent::runner::evm_log& l)
        -> serializer& {
        return ser << l.m_addr << l.m_data << l.m_topics;
    }

    auto operator>>(serializer& deser, threepc::agent::runner::evm_log& l)
        -> serializer& {
        return deser >> l.m_addr >> l.m_data >> l.m_topics;
    }

    auto operator<<(serializer& ser,
                    const threepc::agent::runner::evm_tx_receipt& r)
        -> serializer& {
        return ser << r.m_from << r.m_to << r.m_gas_used << r.m_logs
                   << r.m_output_data;
    }

    auto operator>>(serializer& deser,
                    threepc::agent::runner::evm_tx_receipt& r) -> serializer& {
        return deser >> r.m_from >> r.m_to >> r.m_gas_used >> r.m_logs
            >> r.m_output_data;
    }
}
