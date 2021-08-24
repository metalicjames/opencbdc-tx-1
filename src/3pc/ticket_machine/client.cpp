// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "client.hpp"

#include "util/serialization/format.hpp"

namespace cbdc::threepc::ticket_machine::rpc {
    client::client(std::vector<network::endpoint_t> endpoints)
        : m_client(std::make_unique<decltype(m_client)::element_type>(
            std::move(endpoints))) {}

    auto client::init() -> bool {
        return m_client->init();
    }

    auto
    client::get_ticket_number(get_ticket_number_callback_type result_callback)
        -> bool {
        auto num = std::optional<ticket_number_type>();
        {
            std::unique_lock l(m_mut);
            if(!m_tickets.empty()) {
                num = m_tickets.front();
                m_tickets.pop();
            }
        }
        if(num.has_value()) {
            result_callback(
                ticket_number_range_type{num.value(), num.value()});
            return true;
        }

        return m_client->call(
            std::monostate{},
            [this, result_callback](
                std::optional<get_ticket_number_return_type> res) {
                assert(res.has_value());
                std::visit(
                    overloaded{[&](ticket_number_range_type range) {
                                   {
                                       std::unique_lock ll(m_mut);
                                       for(ticket_number_type i
                                           = range.first + 1;
                                           i < range.second;
                                           i++) {
                                           m_tickets.push(i);
                                       }
                                   }
                                   result_callback(
                                       ticket_number_range_type{range.first,
                                                                range.first});
                               },
                               [&](error_code e) {
                                   result_callback(e);
                               }},
                    res.value());
            });
    }
}
