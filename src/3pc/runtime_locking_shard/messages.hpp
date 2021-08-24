// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_RUNTIME_LOCKING_SHARD_MESSAGES_H_
#define CBDC_UNIVERSE0_SRC_3PC_RUNTIME_LOCKING_SHARD_MESSAGES_H_

#include "interface.hpp"

namespace cbdc::threepc::runtime_locking_shard::rpc {
    /// Try lock request message.
    struct try_lock_request {
        /// Ticket number.
        ticket_number_type m_ticket_number{};
        /// ID of broker managing ticket.
        broker_id_type m_broker_id{};
        /// Key for which to request lock.
        key_type m_key;
        /// Lock type to request.
        lock_type m_locktype{};
    };

    /// Prepare request message.
    struct prepare_request {
        /// Ticket number.
        ticket_number_type m_ticket_number;
        /// State updates to apply.
        state_update_type m_state_updates;
    };

    /// Commit request message.
    struct commit_request {
        /// Ticket number.
        ticket_number_type m_ticket_number;
    };

    /// Rollback request message.
    struct rollback_request {
        /// Ticket number.
        ticket_number_type m_ticket_number;
    };

    /// Finish request message.
    struct finish_request {
        /// Ticket number.
        ticket_number_type m_ticket_number;
    };

    /// Get tickets request message.
    struct get_tickets_request {
        /// Broker ID.
        broker_id_type m_broker_id;
    };

    /// RPC request message type.
    using request = std::variant<try_lock_request,
                                 prepare_request,
                                 commit_request,
                                 rollback_request,
                                 finish_request,
                                 get_tickets_request>;
    /// RPC response message type.
    using response = std::variant<interface::try_lock_return_type,
                                  interface::prepare_return_type,
                                  interface::get_tickets_return_type>;
}

#endif
