// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "impl.hpp"

#include <cassert>

namespace cbdc::threepc::runtime_locking_shard {
    impl::impl(std::shared_ptr<logging::log> logger)
        : m_log(std::move(logger)) {}

    auto impl::try_lock(ticket_number_type ticket_number,
                        broker_id_type broker_id,
                        key_type key,
                        lock_type locktype,
                        try_lock_callback_type result_callback) -> bool {
        auto callbacks = pending_callbacks_list_type();
        auto maybe_error = [&]() -> std::optional<error_code> {
            std::unique_lock<std::mutex> l(m_mut);
            // Grab the ticket or make a new one
            auto& ticket = m_tickets[ticket_number];

            // Callers shouldn't be using try_lock after prepare
            if(ticket.m_state == ticket_state::prepared) {
                m_log->error(ticket_number, "called try_lock after prepare");
                return error_code::prepared;
            }

            if(ticket.m_state == ticket_state::committed) {
                m_log->error(ticket_number, "called try_lock after commit");
                return error_code::committed;
            }

            // If the ticket way wounded don't bother trying to acquire any
            // locks
            if(ticket.m_state == ticket_state::wounded) {
                m_log->trace(ticket_number,
                             "called try_lock after being wounded");
                return error_code::wounded;
            }

            // Make sure the ticket doesn't already hold a lock on the key
            if(auto lock_it = ticket.m_locks_held.find(key);
               lock_it != ticket.m_locks_held.end()
               && lock_it->second >= locktype) {
                m_log->warn(this,
                            ticket_number,
                            "tried to acquire already held lock");
                return error_code::lock_held;
            }

            if(ticket.m_queued_locks.find(key)
               != ticket.m_queued_locks.end()) {
                m_log->warn(ticket_number,
                            "tried to acquire already queued lock");
                return error_code::lock_queued;
            }

            ticket.m_broker_id = broker_id;

            // Grab the requested state element
            auto& state_element = m_state[key];
            auto& lock = state_element.m_lock;

            // Queue the lock
            lock.m_queue.emplace(
                ticket_number,
                lock_queue_element_type{locktype, std::move(result_callback)});
            ticket.m_queued_locks.insert(key);

            // Determine if the ticket will wait on any locks
            auto waiting_on = get_waiting_on(ticket_number, locktype, lock);
            callbacks = wound_tickets(std::move(key), waiting_on);

            m_log->trace(this, "shard handled try_lock for", ticket_number);

            return std::nullopt;
        }();

        if(maybe_error.has_value()) {
            result_callback(maybe_error.value());
        } else {
            // Call all the result callbacks without holding the lock
            for(auto& callback : callbacks) {
                callback.m_callback(std::move(callback.m_returning));
            }
        }

        return true;
    }

    auto impl::wound_tickets(
        key_type key,
        const std::vector<ticket_number_type>& blocking_tickets)
        -> pending_callbacks_list_type {
        auto callbacks = pending_callbacks_list_type();
        auto keys = key_set_type();
        for(auto blocking_ticket_number : blocking_tickets) {
            auto& blocking_ticket = m_tickets[blocking_ticket_number];
            // Tickets can't be deadlocked by prepared tickets and
            // we're not allowed to wound them anyway
            if(blocking_ticket.m_state == ticket_state::prepared) {
                continue;
            }

            // Mark the ticket as wounded
            blocking_ticket.m_state = ticket_state::wounded;

            auto [wounded_callbacks, affected_keys]
                = release_locks(blocking_ticket_number, blocking_ticket);
            callbacks.insert(
                callbacks.end(),
                std::make_move_iterator(wounded_callbacks.begin()),
                std::make_move_iterator(wounded_callbacks.end()));
            keys.merge(affected_keys);
        }

        keys.insert(std::move(key));

        auto acquire_callbacks = acquire_locks(keys);
        callbacks.insert(callbacks.end(),
                         std::make_move_iterator(acquire_callbacks.begin()),
                         std::make_move_iterator(acquire_callbacks.end()));

        return callbacks;
    }

    auto impl::get_waiting_on(ticket_number_type ticket_number,
                              lock_type locktype,
                              rw_lock_type& lock)
        -> std::vector<ticket_number_type> {
        auto waiting_on = std::vector<ticket_number_type>();
        auto younger_ticket = [&](auto blocking_ticket_number) {
            return ticket_number < blocking_ticket_number;
        };
        // Write locks wait on readers
        if(locktype == lock_type::write) {
            std::copy_if(lock.m_readers.begin(),
                         lock.m_readers.end(),
                         std::back_inserter(waiting_on),
                         younger_ticket);
        }
        // All locks wait on writers
        if(lock.m_writer.has_value()) {
            if(younger_ticket(lock.m_writer.value())) {
                waiting_on.push_back(lock.m_writer.value());
            }
        }
        return waiting_on;
    }

    auto impl::prepare(ticket_number_type ticket_number,
                       state_update_type state_update,
                       prepare_callback_type result_callback) -> bool {
        auto result = [&]() -> std::optional<error_code> {
            std::unique_lock<std::mutex> l(m_mut);
            // Grab the ticket and ensure it exists
            auto ticket_it = m_tickets.find(ticket_number);
            if(ticket_it == m_tickets.end()) {
                m_log->error(this,
                             ticket_number,
                             "does not exist on shard for prepare");
                return error_code::unknown_ticket;
            }
            auto& ticket = ticket_it->second;

            // If the ticket is already prepared, return the result as such
            if(ticket.m_state == ticket_state::prepared) {
                m_log->warn(ticket_number,
                            "called prepare but already prepared");
                return error_code::prepared;
            }

            if(ticket.m_state == ticket_state::committed) {
                m_log->warn(ticket_number,
                            "called prepare but already committed");
                return error_code::committed;
            }

            // If the ticket was wounded it can't be prepared
            if(ticket.m_state == ticket_state::wounded) {
                m_log->debug(ticket_number,
                             "called prepare after being wounded");
                return error_code::wounded;
            }

            if(!ticket.m_queued_locks.empty()) {
                m_log->error(ticket_number, "still has queued locks");
                return error_code::lock_queued;
            }

            for(auto& [key, value] : state_update) {
                auto lk_it = ticket.m_locks_held.find(key);
                if(lk_it == ticket.m_locks_held.end()) {
                    m_log->warn(ticket_number,
                                "wanted state update for unheld lock");
                    return error_code::lock_not_held;
                }
                if(lk_it->second != lock_type::write) {
                    m_log->warn(ticket_number,
                                "wanted state update for read lock");
                    return error_code::state_update_with_read_lock;
                }
            }

            ticket.m_state_update = std::move(state_update);
            ticket.m_state = ticket_state::prepared;
            return std::nullopt;
        }();

        result_callback(result);

        return true;
    }

    auto impl::commit(ticket_number_type ticket_number,
                      commit_callback_type result_callback) -> bool {
        auto callbacks = pending_callbacks_list_type();
        auto result = [&]() -> std::optional<error_code> {
            std::unique_lock<std::mutex> l(m_mut);
            // Grab the ticket and ensure it exists
            auto ticket_it = m_tickets.find(ticket_number);
            if(ticket_it == m_tickets.end()) {
                m_log->error(this,
                             ticket_number,
                             "does not exist on shard for commit");
                return error_code::unknown_ticket;
            }
            auto& ticket = ticket_it->second;

            // If the ticket is not prepared we can't commit
            if(ticket.m_state != ticket_state::prepared) {
                m_log->warn(ticket_number, "called commit but not prepared");
                return error_code::not_prepared;
            }

            for(auto&& [key, value] : ticket.m_state_update) {
                m_state[key].m_value = std::move(value);
            }

            auto [wounded_callbacks, affected_keys]
                = release_locks(ticket_number, ticket);
            assert(wounded_callbacks.empty());
            callbacks = acquire_locks(affected_keys);
            callbacks.insert(
                callbacks.end(),
                std::make_move_iterator(wounded_callbacks.begin()),
                std::make_move_iterator(wounded_callbacks.end()));

            ticket.m_state = ticket_state::committed;

            m_log->trace(this, "Shard executed commit for", ticket_number);

            return std::nullopt;
        }();

        for(auto& callback : callbacks) {
            m_log->trace(this,
                         "Shard calling callback for",
                         callback.m_ticket_number);
            callback.m_callback(std::move(callback.m_returning));
        }
        result_callback(result);

        m_log->trace(this,
                     "Shard called all callbacks for commit on",
                     ticket_number);

        return true;
    }

    auto impl::release_locks(ticket_number_type ticket_number,
                             ticket_state_type& ticket)
        -> std::pair<pending_callbacks_list_type, key_set_type> {
        auto callbacks = pending_callbacks_list_type();
        // Unqueue any pending locks
        for(const auto& lock_key : ticket.m_queued_locks) {
            auto& queued_element = m_state[lock_key];
            auto& lk = queued_element.m_lock;
            auto queue_node = lk.m_queue.extract(ticket_number);
            auto& queued_lock_element = queue_node.mapped();
            // Notify the ticket the queued lock was aborted
            callbacks.emplace_back(pending_callback_element_type{
                std::move(queued_lock_element.m_callback),
                error_code::wounded,
                ticket_number});
        }
        auto keys = std::move(ticket.m_queued_locks);
        ticket.m_queued_locks = key_set_type();

        for(auto& [lock_key, lt] : ticket.m_locks_held) {
            // Release any locks held by the blocking ticket
            auto& locked_element = m_state[lock_key];
            auto& lk = locked_element.m_lock;
            // Release the read lock held by the wounded ticket
            if(lt == lock_type::read) {
                lk.m_readers.erase(ticket_number);
            }
            // Release the write lock held by the wounded ticket
            if(lt == lock_type::write) {
                lk.m_writer.reset();
            }
            keys.insert(lock_key);
        }
        ticket.m_locks_held.clear();

        return {callbacks, keys};
    }

    auto impl::acquire_locks(const key_set_type& keys)
        -> pending_callbacks_list_type {
        auto callbacks = pending_callbacks_list_type();
        for(const auto& key : keys) {
            auto& locked_element = m_state[key];
            auto& lk = locked_element.m_lock;
            // Attempt to allow queued tickets to acquire the lock
            bool acquire_next = true;
            while(acquire_next && !lk.m_queue.empty()) {
                auto queue_node = lk.m_queue.begin();
                const auto& queued_ticket_number = queue_node->first;
                auto& queued_lock_element = queue_node->second;
                auto& queued_ticket = m_tickets[queued_ticket_number];
                // Acquire the read lock if the ticket requested a
                // read
                if(queued_lock_element.m_type == lock_type::read) {
                    // If the write lock is held we can't acquire the read lock
                    if(lk.m_writer.has_value()) {
                        break;
                    }
                    lk.m_readers.insert(queued_ticket_number);
                }
                // Acquire the write lock if the ticket requested a
                // write
                if(queued_lock_element.m_type == lock_type::write) {
                    // If there are readers holding the lock we
                    // can't acquire the write lock or allow any
                    // more queued tickets to acquire the lock
                    if(lk.m_readers.size() > 1 || lk.m_writer.has_value()) {
                        break;
                    }
                    if(lk.m_readers.size() == 1) {
                        if(*lk.m_readers.begin() != queued_ticket_number) {
                            break;
                        }

                        // Upgrade from a read to a write lock
                        lk.m_readers.clear();
                    }
                    lk.m_writer = queued_ticket_number;
                    acquire_next = false;
                }
                queued_ticket.m_queued_locks.erase(key);
                queued_ticket.m_locks_held[key] = queued_lock_element.m_type;
                // Notify the ticket that the lock was acquired
                callbacks.emplace_back(pending_callback_element_type{
                    std::move(queued_lock_element.m_callback),
                    locked_element.m_value,
                    queued_ticket_number});
                lk.m_queue.erase(queue_node);
            }
        }
        return callbacks;
    }

    auto impl::rollback(ticket_number_type ticket_number,
                        rollback_callback_type result_callback) -> bool {
        auto callbacks = pending_callbacks_list_type();
        auto result = [&]() -> std::optional<error_code> {
            std::unique_lock<std::mutex> l(m_mut);
            // Grab the ticket and ensure it exists
            auto ticket_it = m_tickets.find(ticket_number);
            if(ticket_it == m_tickets.end()) {
                m_log->error(this,
                             ticket_number,
                             "does not exist on shard for rollback");
                return error_code::unknown_ticket;
            }
            auto& ticket = ticket_it->second;

            auto [wounded_callbacks, affected_keys]
                = release_locks(ticket_number, ticket);
            callbacks = acquire_locks(affected_keys);
            callbacks.insert(
                callbacks.end(),
                std::make_move_iterator(wounded_callbacks.begin()),
                std::make_move_iterator(wounded_callbacks.end()));

            // We erase the ticket here as we won't need the ticket for
            // recovery. No need for a "rolled back" state and subsequent
            // finish.
            m_tickets.erase(ticket_it);

            m_log->trace(this, "Shard handled rollback for", ticket_number);

            return std::nullopt;
        }();

        for(auto& callback : callbacks) {
            callback.m_callback(std::move(callback.m_returning));
        }
        result_callback(result);

        return true;
    }

    auto impl::finish(ticket_number_type ticket_number,
                      finish_callback_type result_callback) -> bool {
        auto maybe_error = [&]() -> std::optional<error_code> {
            std::unique_lock l(m_mut);
            auto ticket_it = m_tickets.find(ticket_number);
            if(ticket_it == m_tickets.end()) {
                m_log->error(this,
                             ticket_number,
                             "does not exist on shard for finish");
                return error_code::unknown_ticket;
            }

            auto& ticket = ticket_it->second;

            if(ticket.m_state != ticket_state::committed) {
                m_log->error(this,
                             ticket_number,
                             "finish requested but not committed");
                return error_code::not_committed;
            }

            m_tickets.erase(ticket_it);

            m_log->trace(this, "Shard handled finish for", ticket_number);

            return std::nullopt;
        }();

        result_callback(maybe_error);

        return true;
    }

    auto impl::get_tickets(broker_id_type broker_id,
                           get_tickets_callback_type result_callback) -> bool {
        auto result = [&]() -> get_tickets_success_type {
            std::unique_lock l(m_mut);
            auto ret = get_tickets_success_type();
            for(auto& [ticket_number, ticket] : m_tickets) {
                if(ticket.m_broker_id == broker_id) {
                    ret.emplace(ticket_number, ticket.m_state);
                }
            }
            return ret;
        }();

        result_callback(result);

        return true;
    }
}
