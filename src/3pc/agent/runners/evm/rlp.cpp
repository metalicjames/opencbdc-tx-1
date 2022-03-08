// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "rlp.hpp"

namespace cbdc {
    rlp_value::rlp_value(rlp_value_type type) : m_type(type) {}
    rlp_value::rlp_value(const buffer& data) : m_type(rlp_value_type::buffer) {
        assign(data);
    }
    void rlp_value::assign(const buffer& data) {
        m_buffer.clear();
        m_buffer.extend(data.size());
        std::memcpy(m_buffer.data(), data.data(), data.size());
    }
    auto rlp_value::push_back(const rlp_value& val) -> bool {
        auto ret = (m_type == rlp_value_type::array);
        if(ret) {
            m_values.push_back(val);
        }
        return ret;
    }
}
