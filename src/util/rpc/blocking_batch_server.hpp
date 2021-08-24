// Copyright (c) 2021 MIT Digital Currency Initiative,
//                    Federal Reserve Bank of Boston
// Distributed under the MIT software license, see the accompanying
// file COPYING or http://www.opensource.org/licenses/mit-license.php.

#ifndef CBDC_UNIVERSE0_SRC_RPC_BLOCKING_BATCH_SERVER_H_
#define CBDC_UNIVERSE0_SRC_RPC_BLOCKING_BATCH_SERVER_H_

#include "server.hpp"

namespace cbdc::rpc {
    /// Generic synchronous RPC server. Handles serialization of requests and
    /// responses. Dispatches incoming requests to a handler callback for
    /// processing. Subclass to define specific remote communication logic.
    /// Handles the case where processing an RPC results in zero or more
    /// responses to previous RPCs.
    /// \tparam Request type for requests.
    /// \tparam Response type for responses.
    /// \tparam InBuffer type of buffer for serialized requests, defaults to
    ///         \ref cbdc::buffer
    /// \tparam OutBuffer type of buffer for serialized responses, defaults to
    ///         \ref cbdc::buffer
    template<typename Request,
             typename Response,
             typename InBuffer = buffer,
             typename OutBuffer = buffer>
    class blocking_batch_server
        : public server<Request, Response, InBuffer, OutBuffer> {
      public:
        blocking_batch_server() = default;
        blocking_batch_server(blocking_batch_server&&) noexcept = default;
        auto operator=(blocking_batch_server&&) noexcept
            -> blocking_batch_server& = default;
        blocking_batch_server(const blocking_batch_server&) = default;
        auto operator=(const blocking_batch_server&)
            -> blocking_batch_server& = default;

        ~blocking_batch_server() override = default;

        static constexpr handler_type handler = handler_type::blocking;

        using server_type = server<Request, Response, InBuffer, OutBuffer>;

        /// RPC request type. Unique request ID and request value.
        using request_type = std::pair<size_t, Request>;
        /// RPC response type. Unique request ID and response value.
        using response_type = std::pair<size_t, Response>;
        /// Result from processing an RPC. A vector of responses to previous
        /// RPCs, or std::nullopt if there was an error processing the RPC.
        using callback_return_type = std::optional<std::vector<response_type>>;
        /// Handler callback function type which accepts a request and returns
        /// a vector of responses, or returns std::nullopt if it encounters an
        /// error while processing the request.
        using callback_type
            = std::function<callback_return_type(request_type)>;

        /// Register a handler callback function for processing requests and
        /// returning responses.
        /// \param callback function to register to process client requests and
        ///                 return responses.
        void register_handler_callback(callback_type callback) {
            m_callback = std::move(callback);
        }

      protected:
        /// Synchronously deserializes an RPC request, calls the request
        /// handler function, then serializes and returns the list responses.
        /// \param request_buf buffer holding an RPC request.
        /// \return serialized list of responses, or std::nullopt if
        ///         deserializing or handling the request failed.
        auto blocking_call(InBuffer request_buf) -> std::optional<OutBuffer> {
            auto req = from_buffer<request_type>(request_buf);
            if(!req.has_value()) {
                return std::nullopt;
            }
            if(!m_callback) {
                return std::nullopt;
            }
            auto resp = m_callback(req.value());
            return make_buffer<decltype(resp), OutBuffer>(resp);
        }

      private:
        callback_type m_callback;
    };
}

#endif
