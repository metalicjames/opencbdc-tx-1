// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNER_H_
#define CBDC_UNIVERSE0_SRC_3PC_AGENT_RUNNER_H_

#include "3pc/broker/interface.hpp"
#include "interface.hpp"
#include "util/common/logging.hpp"

#include <lua.hpp>
#include <memory>

namespace cbdc::threepc::agent {
    /// Lua function executor. Provides an environment for contracts to execute
    /// in. Manages retrieval of function bytecode, locking keys during
    /// function execution, signature checking and commiting execution results.
    /// Class cannot be re-used for different functions/transactions, manages
    /// the lifecycle of a single transaction.
    class runner {
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
            /// Lua error during function execution.
            exec_error,
            /// Error loading function bytecode.
            function_load,
            /// Internal Lua error.
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
        runner(std::shared_ptr<logging::log> logger,
               runtime_locking_shard::value_type function,
               parameter_type param,
               run_callback_type result_callback,
               try_lock_callback_type try_lock_callback);

        /// Begins function execution. Retrieves the function bytecode using a
        /// read lock and executes it with the given parameter.
        /// \return true.
        auto run() -> bool;

      private:
        std::shared_ptr<logging::log> m_log;
        std::shared_ptr<lua_State> m_state;
        runtime_locking_shard::value_type m_function;
        parameter_type m_param;
        run_callback_type m_result_callback;
        try_lock_callback_type m_try_lock_callback;

        void contract_epilogue(int n_results);

        auto get_stack_string(int index) -> std::optional<buffer>;

        void schedule_contract();

        void
        handle_try_lock(const broker::interface::try_lock_return_type& res);

        static auto check_sig(lua_State* L) -> int;
    };
}

#endif
