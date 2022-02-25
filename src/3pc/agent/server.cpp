// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#include "server.hpp"

#include "3pc/agent/runners/evm/impl.hpp"
#include "impl.hpp"

#include <cassert>
#include <future>

namespace cbdc::threepc::agent::rpc {
    server::server(std::unique_ptr<server_type> srv,
                   std::shared_ptr<broker::interface> broker,
                   std::shared_ptr<logging::log> log)
        : m_srv(std::move(srv)),
          m_broker(std::move(broker)),
          m_log(std::move(log)) {
        m_srv->register_handler_callback(
            [&](request req, server_type::response_callback_type callback) {
                return request_handler(std::move(req), std::move(callback));
            });
        m_cleanup_thread = std::thread([&]() {
            size_t id{};
            while(m_cleanup_queue.pop(id)) {
                std::unique_lock l(m_agents_mut);
                m_agents.erase(id);
            }
        });
        m_retry_thread = std::thread([&]() {
            size_t id{};
            while(m_retry_queue.pop(id)) {
                auto a = [&]() {
                    std::unique_lock l(m_agents_mut);
                    auto it = m_agents.find(id);
                    assert(it != m_agents.end());
                    return it->second;
                }();
                if(!a->exec()) {
                    m_log->fatal("Error retrying agent");
                }
            }
        });
    }

    server::~server() {
        m_srv.reset();
        m_cleanup_queue.clear();
        m_cleanup_thread.join();
        m_retry_queue.clear();
        m_retry_thread.join();
        {
            std::unique_lock l(m_agents_mut);
            m_agents.clear();
        }
    }

    auto server::request_handler(request req,
                                 server_type::response_callback_type callback)
        -> bool {
        auto id = m_next_id++;
        auto a = [&]() {
            auto agent = std::make_shared<impl>(
                m_log,
                &runner::factory<runner::evm_runner>::create,
                m_broker,
                req.m_function,
                req.m_param,
                [this, id, callback](interface::exec_return_type res) {
                    auto success = std::holds_alternative<return_type>(res);
                    if(!success) {
                        auto ec = std::get<interface::error_code>(res);
                        if(ec == interface::error_code::retry) {
                            m_retry_queue.push(id);
                            return;
                        }
                    }
                    callback(res);
                    m_cleanup_queue.push(id);
                });
            {
                std::unique_lock l(m_agents_mut);
                m_agents.emplace(id, agent);
            }
            return agent;
        }();
        return a->exec();
    }
}
