// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "format.hpp"

#include "util/serialization/format.hpp"

namespace cbdc {
    auto operator<<(
        serializer& ser,
        const threepc::runtime_locking_shard::rpc::try_lock_request& req)
        -> serializer& {
        return ser << req.m_ticket_number << req.m_broker_id << req.m_key
                   << req.m_locktype;
    }
    auto operator>>(serializer& deser,
                    threepc::runtime_locking_shard::rpc::try_lock_request& req)
        -> serializer& {
        return deser >> req.m_ticket_number >> req.m_broker_id >> req.m_key
            >> req.m_locktype;
    }

    auto
    operator<<(serializer& ser,
               const threepc::runtime_locking_shard::rpc::commit_request& req)
        -> serializer& {
        return ser << req.m_ticket_number;
    }
    auto operator>>(serializer& deser,
                    threepc::runtime_locking_shard::rpc::commit_request& req)
        -> serializer& {
        return deser >> req.m_ticket_number;
    }

    auto
    operator<<(serializer& ser,
               const threepc::runtime_locking_shard::rpc::prepare_request& req)
        -> serializer& {
        return ser << req.m_ticket_number << req.m_state_updates;
    }
    auto operator>>(serializer& deser,
                    threepc::runtime_locking_shard::rpc::prepare_request& req)
        -> serializer& {
        return deser >> req.m_ticket_number >> req.m_state_updates;
    }

    auto operator<<(
        serializer& ser,
        const threepc::runtime_locking_shard::rpc::rollback_request& req)
        -> serializer& {
        return ser << req.m_ticket_number;
    }
    auto operator>>(serializer& deser,
                    threepc::runtime_locking_shard::rpc::rollback_request& req)
        -> serializer& {
        return deser >> req.m_ticket_number;
    }

    auto
    operator<<(serializer& ser,
               const threepc::runtime_locking_shard::rpc::finish_request& req)
        -> serializer& {
        return ser << req.m_ticket_number;
    }
    auto operator>>(serializer& deser,
                    threepc::runtime_locking_shard::rpc::finish_request& req)
        -> serializer& {
        return deser >> req.m_ticket_number;
    }

    auto operator<<(
        serializer& ser,
        const threepc::runtime_locking_shard::rpc::get_tickets_request& req)
        -> serializer& {
        return ser << req.m_broker_id;
    }
    auto
    operator>>(serializer& deser,
               threepc::runtime_locking_shard::rpc::get_tickets_request& req)
        -> serializer& {
        return deser >> req.m_broker_id;
    }
}
