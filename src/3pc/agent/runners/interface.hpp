// Copyright (c) 2022 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_INTERFACE_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNERS_INTERFACE_H_

#include "3pc/agent/interface.hpp"
#include "3pc/broker/interface.hpp"
#include "3pc/runtime_locking_shard/interface.hpp"
#include "util/common/logging.hpp"

#include <memory>

namespace cbdc::threepc::agent::runner {
    class interface {
      public:
        /// Error codes return during function execution.
        enum class error_code {
            /// Function did not return a string value.
            result_value_type,
            /// Function did not return a string key.
            result_key_type,
            /// Function did not return a map.
            result_type,
            /// Function more than one result.
            result_count,
            /// Runner error during function execution.
            exec_error,
            /// Error loading function bytecode.
            function_load,
            /// Internal Runner error.
            internal_error,
            /// Function yielded more than one key to lock.
            yield_count,
            /// Function yielded a non-string key.
            yield_type,
            /// Error acquiring lock on key.
            lock_error,
            /// Ticket wounded during execution.
            wounded
        };

        /// Return type from executing a function. Either the state updates
        /// committed after function execution or an error code.
        using run_return_type
            = std::variant<runtime_locking_shard::state_update_type,
                           error_code>;
        /// Callback type for function execution.
        using run_callback_type = std::function<void(run_return_type)>;

        /// Callback function type for acquiring locks during function
        /// execution. Accepts a key to lock and function to call with lock
        /// result. Returns true if request was initiated successfully.
        using try_lock_callback_type
            = std::function<bool(broker::key_type,
                                 broker::interface::try_lock_callback_type)>;

        /// Constructor.
        /// \param logger log instance.
        /// \param function key of function bytecode to execute.
        /// \param param parameter to pass to function.
        /// \param result_callback function to call with function execution
        ///                        result.
        /// \param try_lock_callback function to call for the function to
        ///                          request key locks.
        interface(std::shared_ptr<logging::log> logger,
                  runtime_locking_shard::value_type function,
                  parameter_type param,
                  run_callback_type result_callback,
                  try_lock_callback_type try_lock_callback);

        virtual ~interface() = default;

        interface(const interface&) = delete;
        auto operator=(const interface&) -> interface& = delete;
        interface(interface&&) = delete;
        auto operator=(interface&&) -> interface& = delete;

        /// Begins function execution. Retrieves the function bytecode using a
        /// read lock and executes it with the given parameter.
        /// \return true.
        virtual auto run() -> bool = 0;

        friend class lua_runner;

      private:
        std::shared_ptr<logging::log> m_log;
        runtime_locking_shard::value_type m_function;
        parameter_type m_param;
        run_callback_type m_result_callback;
        try_lock_callback_type m_try_lock_callback;
    };
}

#endif
