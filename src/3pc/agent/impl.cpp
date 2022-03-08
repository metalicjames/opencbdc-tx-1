// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "impl.hpp"

#include "util/common/variant_overloaded.hpp"

namespace cbdc::threepc::agent {
    impl::impl(std::shared_ptr<logging::log> logger,
               cbdc::threepc::config cfg,
               runner::interface::factory_type runner_factory,
               std::shared_ptr<broker::interface> broker,
               runtime_locking_shard::key_type function,
               parameter_type param,
               exec_callback_type result_callback,
               broker::lock_type initial_lock_type)
        : interface(std::move(function),
                    std::move(param),
                    std::move(result_callback)),
          m_log(std::move(logger)),
          m_cfg(std::move(cfg)),
          m_runner_factory(std::move(runner_factory)),
          m_broker(std::move(broker)),
          m_initial_lock_type(initial_lock_type) {}

    auto impl::exec() -> bool {
        std::unique_lock l(m_mut);
        switch(m_state) {
            // In these states we can start again from the beginning
            case state::init:
                [[fallthrough]];
            case state::begin_sent:
            case state::begin_failed:
                break;

            // We already have a ticket number but need to start again
            case state::rollback_complete:
                m_result = std::nullopt;
                do_start();
                return true;

            // Re-run commit
            case state::commit_failed:
                [[fallthrough]];
            case state::commit_sent:
                do_commit();
                return true;

            // Re-run rollback with prior error type flag
            case state::rollback_failed:
                [[fallthrough]];
            case state::rollback_sent:
                do_rollback(m_permanent_error);
                return true;

            // Rollback first so we can start fresh
            case state::function_get_sent:
                [[fallthrough]];
            case state::function_get_failed:
            case state::function_failed:
            case state::function_started:
                do_rollback(false);
                return true;

            // Re-run finish
            case state::finish_sent:
                [[fallthrough]];
            case state::finish_failed:
                // Committed but transient error running finish, cannot
                // rollback, need to retry finish
                do_finish();
                return true;

            // End states, cannot re-run exec
            case state::function_get_error:
                [[fallthrough]];
            case state::commit_error:
            case state::function_error:
            case state::finish_complete:
                return true;
        }

        m_result = std::nullopt;
        m_state = state::begin_sent;
        auto success
            = m_broker->begin([&](broker::interface::begin_return_type res) {
                  handle_begin(res);
              });

        if(!success) {
            m_state = state::begin_failed;
            m_log->error("Failed to contact broker to begin");
            m_result = error_code::broker_unreachable;
            do_result();
        }

        return true;
    }

    void impl::handle_begin(broker::interface::begin_return_type res) {
        std::unique_lock l(m_mut);
        if(m_state != state::begin_sent) {
            m_log->warn("handle_begin while not in begin_sent state");
            return;
        }
        std::visit(
            overloaded{[&](const ticket_machine::ticket_number_type& n) {
                           m_ticket_number = n;
                           do_start();
                       },
                       [&](const broker::interface::error_code& /* e */) {
                           m_state = state::begin_failed;
                           m_log->error(
                               "Broker failed to assign a ticket number");
                           m_result = error_code::ticket_number_assignment;
                           do_result();
                       }},
            res);
    }

    void impl::do_start() {
        std::unique_lock l(m_mut);
        assert(m_ticket_number.has_value());
        assert(m_state == state::begin_sent
               || m_state == state::rollback_complete);
        m_state = state::function_get_sent;
        auto tl_success = m_broker->try_lock(
            m_ticket_number.value(),
            get_function(),
            m_initial_lock_type,
            [this](const broker::interface::try_lock_return_type& lock_res) {
                handle_function(lock_res);
            });
        if(!tl_success) {
            m_state = state::function_get_failed;
            m_log->error("Failed to contact broker to retrieve "
                         "function code");
            m_result = error_code::broker_unreachable;
            do_result();
        }
    }

    void impl::handle_try_lock_response(
        const broker::interface::try_lock_callback_type& res_cb,
        broker::interface::try_lock_return_type res) {
        std::unique_lock l(m_mut);
        if(m_state != state::function_started) {
            m_log->error("try_lock response while not in "
                         "function_started state");
            return;
        }
        res_cb(std::move(res));
    }

    auto impl::handle_try_lock_request(
        broker::key_type key,
        broker::interface::try_lock_callback_type res_cb) -> bool {
        // TODO: allow contracts to acquire read locks
        // TODO: permissions for keys
        std::unique_lock l(m_mut);
        assert(m_ticket_number.has_value());
        if(m_state != state::function_started) {
            m_log->warn(
                "handle_try_lock_request while not in function_started state");
            return false;
        }
        return m_broker->try_lock(
            m_ticket_number.value(),
            std::move(key),
            broker::lock_type::write,
            [this, cb = std::move(res_cb)](
                broker::interface::try_lock_return_type res) {
                handle_try_lock_response(cb, std::move(res));
            });
    }

    void
    impl::handle_function(const broker::interface::try_lock_return_type& res) {
        std::unique_lock l(m_mut);
        if(m_state != state::function_get_sent) {
            m_log->warn(
                "handle_function while not in function_get_sent state");
            return;
        }
        std::visit(
            overloaded{
                [&](broker::value_type v) {
                    m_state = state::function_started;
                    m_runner = m_runner_factory(
                        m_log,
                        m_cfg,
                        std::move(v),
                        get_param(),
                        [this](const runner::interface::run_return_type&
                                   run_res) {
                            handle_run(run_res);
                        },
                        [this](
                            broker::key_type key,
                            broker::interface::try_lock_callback_type res_cb)
                            -> bool {
                            return handle_try_lock_request(std::move(key),
                                                           std::move(res_cb));
                        });
                    auto run_res = m_runner->run();
                    if(!run_res) {
                        m_state = state::function_failed;
                        m_log->error("Failed to start contract execution");
                        m_result = error_code::function_execution;
                        do_result();
                    }
                },
                [&](broker::interface::error_code /* e */) {
                    m_state = state::function_get_failed;
                    m_log->error("Failed to retrieve function");
                    m_result = error_code::function_retrieval;
                    do_result();
                },
                [&](runtime_locking_shard::error_code e) {
                    if(e == runtime_locking_shard::error_code::wounded) {
                        m_state = state::function_get_failed;
                        m_log->trace(
                            "Shard wounded ticket while retrieving function");
                    } else {
                        m_state = state::function_get_error;
                        m_log->error("Shard error retrieving function");
                    }
                    m_result = error_code::function_retrieval;
                    do_result();
                }},
            res);
    }

    void impl::do_commit() {
        std::unique_lock l(m_mut);
        assert(m_state == state::function_started
               || m_state == state::commit_failed
               || m_state == state::commit_sent);
        assert(m_result.has_value());
        assert(m_ticket_number.has_value());
        assert(std::holds_alternative<broker::state_update_type>(
            m_result.value()));
        m_state = state::commit_sent;
        m_log->trace(this,
                     "Agent requesting commit for",
                     m_ticket_number.value());
        auto maybe_success = m_broker->commit(
            m_ticket_number.value(),
            std::get<broker::state_update_type>(m_result.value()),
            [this](broker::interface::commit_return_type commit_res) {
                handle_commit(commit_res);
            });
        if(!maybe_success) {
            m_state = state::commit_failed;
            m_log->error("Failed to contact broker for commit");
            m_result = error_code::broker_unreachable;
            do_result();
        }
    }

    void impl::handle_run(const runner::interface::run_return_type& res) {
        std::unique_lock l(m_mut);
        if(m_state != state::function_started) {
            m_log->warn("handle_run while not in function_started state");
            return;
        }
        std::visit(
            overloaded{
                [&](runtime_locking_shard::state_update_type states) {
                    m_result = std::move(states);
                    do_commit();
                },
                [&](runner::interface::error_code e) {
                    if(e == runner::interface::error_code::wounded
                       || e == runner::interface::error_code::internal_error) {
                        m_state = state::function_failed;
                    } else {
                        m_state = state::function_error;
                        m_log->error("Function execution failed");
                    }
                    m_result = error_code::function_execution;
                    do_result();
                }},
            res);
        m_log->trace(this,
                     "Agent handle_run complete for",
                     m_ticket_number.value());
    }

    void impl::handle_commit(broker::interface::commit_return_type res) {
        std::unique_lock l(m_mut);
        if(m_state != state::commit_sent) {
            m_log->warn(
                this,
                "Agent handle_commit while not in commit_sent state for",
                m_ticket_number.value(),
                "actual state:");
            return;
        }
        if(res.has_value()) {
            std::visit(
                overloaded{
                    [&](broker::interface::error_code /* e */) {
                        m_state = state::commit_failed;
                        m_log->error("Broker error for commit for",
                                     m_ticket_number.value());
                        m_result = error_code::commit_error;
                        do_result();
                    },
                    [&](runtime_locking_shard::error_code e) {
                        if(e == runtime_locking_shard::error_code::wounded) {
                            m_state = state::commit_failed;
                            m_log->trace(m_ticket_number.value(),
                                         "wounded during commit");
                        } else {
                            m_state = state::commit_error;
                            m_log->error("Shard error for commit for",
                                         m_ticket_number.value());
                        }
                        m_result = error_code::commit_error;
                        do_result();
                    }},
                res.value());
        } else {
            m_log->trace(this,
                         "Agent handled commit for",
                         m_ticket_number.value());
            do_finish();
        }
    }

    void impl::do_result() {
        std::unique_lock l(m_mut);
        assert(m_result.has_value());
        switch(m_state) {
            // No results should be reported in these states, fatal bugs
            case state::init:
                m_log->fatal("Result reported in initial state");
            case state::begin_sent:
                m_log->fatal("Result reported in begin_sent state");
            case state::function_get_sent:
                m_log->fatal("Result reported in function_get_sent state");
            case state::commit_sent:
                m_log->fatal("Result reported in commit_sent state");
            case state::finish_sent:
                m_log->fatal("Result reported in finish_sent state");
            case state::function_started:
                m_log->fatal("Result reported in function_started state");
            case state::rollback_sent:
                m_log->fatal("Result reported in rollback_sent state");
            case state::rollback_complete:
                if(!std::holds_alternative<error_code>(m_result.value())
                   || std::get<error_code>(m_result.value())
                          != error_code::retry) {
                    m_log->fatal("Result reported in rollback_complete state "
                                 "when result is not retry");
                }
                [[fallthrough]];

            // Failure due to transient problems, should retry
            case state::begin_failed:
                // Couldn't get a ticket number, no need to rollback
                break;

            case state::function_get_failed:
                [[fallthrough]];
            case state::function_failed:
            case state::commit_failed:
                do_rollback(false);
                return;

            case state::finish_failed:
                // Committed but transient error running finish, cannot
                // rollback, need to retry finish
                [[fallthrough]];
            case state::rollback_failed:
                // Need to retry rollback
                break;

            // Failure due to permanent error, abort completely
            case state::function_get_error:
                [[fallthrough]];
            case state::commit_error:
            case state::function_error:
                do_rollback(true);
                return;

            // Ran to completion
            case state::finish_complete:
                m_log->debug(this, "Agent finished", m_ticket_number.value());
                break;
        }
        get_result_callback()(m_result.value());
        m_log->trace(this,
                     "Agent handled result for",
                     m_ticket_number.value());
    }

    void impl::do_finish() {
        std::unique_lock l(m_mut);
        assert(m_state == state::commit_sent || m_state == state::finish_failed
               || m_state == state::finish_sent
               || m_state == state::rollback_complete);
        assert(m_ticket_number.has_value());
        m_state = state::finish_sent;
        m_log->trace(this,
                     "Agent requesting finish for",
                     m_ticket_number.value());
        auto maybe_success = m_broker->finish(
            m_ticket_number.value(),
            [this](broker::interface::finish_return_type finish_res) {
                handle_finish(finish_res);
            });
        if(!maybe_success) {
            m_state = state::finish_failed;
            m_log->error("Error contacting broker for finish");
            m_result = error_code::broker_unreachable;
            do_result();
        }
    }

    void
    impl::handle_finish(broker::interface::finish_return_type finish_res) {
        std::unique_lock l(m_mut);
        if(m_state != state::finish_sent) {
            m_log->warn("handle_finish while not in finish_sent state");
            return;
        }
        if(finish_res.has_value()) {
            m_state = state::finish_failed;
            m_log->error("Broker error for finish for",
                         m_ticket_number.value());
            m_result = error_code::finish_error;
            do_result();
        } else {
            m_state = state::finish_complete;
            m_log->trace(this,
                         "Agent handled finish for",
                         m_ticket_number.value());
            do_result();
        }
    }

    void impl::do_rollback(bool finish) {
        std::unique_lock l(m_mut);
        assert(m_state == state::commit_failed
               || m_state == state::rollback_sent
               || m_state == state::function_error
               || m_state == state::function_failed
               || m_state == state::commit_error
               || m_state == state::function_get_failed
               || m_state == state::function_get_error
               || m_state == state::function_started
               || m_state == state::rollback_failed);
        assert(m_ticket_number.has_value());
        m_log->trace(this, "Agent rolling back", m_ticket_number.value());
        m_state = state::rollback_sent;
        m_permanent_error = finish;
        auto maybe_success = m_broker->rollback(
            m_ticket_number.value(),
            [this](broker::interface::rollback_return_type rollback_res) {
                handle_rollback(rollback_res);
            });
        if(!maybe_success) {
            m_state = state::rollback_failed;
            m_log->error("Error contacting broker for rollback");
            m_result = error_code::broker_unreachable;
            do_result();
        }
    }

    void impl::handle_rollback(
        broker::interface::rollback_return_type rollback_res) {
        std::unique_lock l(m_mut);
        if(m_state != state::rollback_sent) {
            m_log->warn("handle_rollback while not in rollback_sent state");
            return;
        }
        if(rollback_res.has_value()) {
            m_state = state::rollback_failed;
            m_result = error_code::rollback_error;
            m_log->error("Broker error rolling back", m_ticket_number.value());
            do_result();
            return;
        }

        m_state = state::rollback_complete;
        m_log->trace(this, "Agent rolled back", m_ticket_number.value());
        if(m_permanent_error) {
            m_log->trace(this,
                         "Agent finishing due to permanent error",
                         m_ticket_number.value());
            do_finish();
        } else {
            // Transient error, try again
            m_log->debug(this,
                         "Agent should restart",
                         m_ticket_number.value());
            m_result = error_code::retry;
            do_result();
        }
    }

    impl::~impl() {
        std::unique_lock l(m_mut);
        if(m_state != state::finish_complete) {
            m_log->fatal(
                this,
                "Agent state wasn't finished at destruction, state was:",
                static_cast<int>(m_state));
        }
    }

    auto impl::get_ticket_number() const
        -> std::optional<ticket_machine::ticket_number_type> {
        std::unique_lock l(m_mut);
        return m_ticket_number;
    }

    auto impl::get_state() const -> state {
        std::unique_lock l(m_mut);
        return m_state;
    }
}
