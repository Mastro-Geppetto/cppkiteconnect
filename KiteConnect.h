#pragma once

#include <string>
#include <map>
#include <list>
#include <functional>
#include <algorithm>
#include <cctype>
#include <initializer_list>

#include <cpr/cpr.h>
#include <nlohmann/json.hpp>
#include "utils.h"
#include "KiteException.h"

#include <boost/regex.hpp>
#include <boost/log/trivial.hpp>
#include <boost/log/utility/setup.hpp>
#include <fmt/core.h>
#include <fmt/format.h>

using namespace fmt::literals; //  _a and _format
using json = nlohmann::json;


namespace kite
{
    // _DEFAULT_BASE_URI: Default root API endpoint.It's possible to
    // override this by passing the `root` parameter during initialisation.
    // URIs to various calls
    const std::string _DEFAULT_API_URI = "https://api.kite.trade";
    const std::string _DEFAULT_LOGIN_URI =  "https://kite.trade/connect/login";

    const int _default_timeout = 7;  //In seconds

    const std::map <std::string, std::string> _routes
    {
        {"parameters", "/parameters"},

        {"api.token"                ,   "/session/token"},
        {"api.token.refresh"      ,   "/session/refresh_token"},
        {"api.token.invalidate"  ,   "/session/token"} ,

        {"instrument.margins"  ,  "/margins/{segment}"},
        
        {"user.profile"                 ,  "/user/profile"},
        {"user.margins"              ,  "/user/margins"},
        {"user.margins.segment" ,  "/user/margins/{segment}"},

        {"orders"                      , "/orders"},
        {"trades"                      , "/trades"},

        // TODO CHECK ALL THE BELOW IF THEY WORK ?
        {"order.info"       ,  "/orders/{order_id}"},
        {"order.place"     ,  "/orders/{variety}"},
        {"order.modify"  ,  "/orders/{variety}/{order_id}"},
        {"order.cancel"   ,  "/orders/{variety}/{order_id}"},
        {"order.trades"   ,  "/orders/{order_id}/trades"},

        {"portfolio.positions"            ,  "/portfolio/positions"},
        {"portfolio.holdings"            ,  "/portfolio/holdings"},
        {"portfolio.positions.convert"    ,  "/portfolio/positions"},
        
        // instruments
        {"market.instruments.all"    ,  "/instruments"},
        {"market.instruments"        ,  "/instruments/{exchange}"},
        // OHLCV data
        {"market.quote"                 ,  "/quote"},
        {"market.ohlc"                   ,  "/quote/ohlc"},
        {"market.ltp"                     ,  "/quote/ltp"},
        {"market.historical"            ,  "/instruments/historical/{instrument_token}/{interval}"},
        // trigger range for bracket order
        {"market.trigger_range"     ,  "/instruments/trigger_range/{transaction_type}"},

    };

    // Constants
    const std::string API_KEY = "kitefront";
    const cpr::Header HEADER = {
        {"User-Agent"         , "Mozilla/5.0 (Windows NT 10.0; WOW64; rv:56.0) Gecko/20100101 Firefox/56.0" },
        {"Referer"              , "https://kite.zerodha.com/"},
        {"Host"                  , "kite.zerodha.com"},
        //{"Accept-Encoding"    , "gzip, deflate, br"}, // CPR Doesn't have support for this
        //{"Connection"       ,"close"}, // close, don't keep alive
        // https://curl.haxx.se/libcurl/c/CURLOPT_ACCEPT_ENCODING.html
        {"Accept"               , "application / json, text / plain"},
        {"Connection"         , "keep-alive"},
        {"dnt"                    , "1" },
        {"accept - language", "en - US,en; q = 0.9"},
    };


    // Products
    const std::string PRODUCT_MIS = "MIS";
    const std::string PRODUCT_CNC = "CNC";
    const std::string PRODUCT_NRML = "NRML";
    const std::string PRODUCT_CO = "CO";
    const std::string PRODUCT_BO = "BO";

    // Order types
    const std::string ORDER_TYPE_MARKET = "MARKET";
    const std::string ORDER_TYPE_LIMIT = "LIMIT";
    const std::string ORDER_TYPE_SLM = "SL-M";
    const std::string ORDER_TYPE_SL = "SL";

    // Varities
    const std::string VARIETY_REGULAR = "regular";
    const std::string VARIETY_BO = "bo";
    const std::string VARIETY_CO = "co";
    const std::string VARIETY_AMO = "amo";

    // Transaction type
    const std::string TRANSACTION_TYPE_BUY = "BUY";
    const std::string TRANSACTION_TYPE_SELL = "SELL";

    // Validity
    const std::string VALIDITY_DAY = "DAY";
    const std::string VALIDITY_IOC = "IOC";

    // Exchanges
    const std::string EXCHANGE_NSE = "NSE";
    const std::string EXCHANGE_BSE = "BSE";
    const std::string EXCHANGE_NFO = "NFO";
    const std::string EXCHANGE_CDS = "CDS";
    const std::string EXCHANGE_BFO = "BFO";
    const std::string EXCHANGE_MCX = "MCX";

    // Margins segments
    const std::string MARGIN_EQUITY = "equity";
    const std::string MARGIN_COMMODITY = "commodity";

    // Status constants
    const std::string STATUS_COMPLETE = "COMPLETE";
    const std::string STATUS_REJECTED = "REJECTED";
    const std::string STATUS_CANCELLED = "CANCELLED";


    typedef enum { GET, DELETE, POST, PUT, PATCH, HEAD, OPTIONS } httpReq;
    const std::map<httpReq, std::string> httpVerbMap = {
        { GET,        "GET"},
        { DELETE,   "DELETE"},
        { POST,      "POST"},
        { PUT,        "PUT" },
        { PATCH,    "PATCH" },
        { HEAD,     "HEAD" },
        { OPTIONS,"OPTIONS" }
    };

    /*=======================================================*/
    ///
    /// Start of utility Functions
    ///
    /*=======================================================*/

    /// 1. First function is logger function & must be invoked first
    static void init_log()
    {
        /*!
        @usage Example
            BOOST_LOG_TRIVIAL(trace) << "A trace severity message";
            BOOST_LOG_TRIVIAL(debug) << "A debug severity message";
            BOOST_LOG_TRIVIAL(info) << "An informational severity message";
            BOOST_LOG_TRIVIAL(warning) << "A warning severity message";
            BOOST_LOG_TRIVIAL(error) << "An error severity message";
            BOOST_LOG_TRIVIAL(fatal) << "A fatal severity message";
        */

        static const std::string COMMON_FMT("[%TimeStamp%][%Severity%]:  %Message%");

        boost::log::register_simple_formatter_factory< boost::log::trivial::severity_level, char >("Severity");

        // Output message to console
        /* by commenting below lines i have added a console sink */
        /*boost::log::add_console_log(
            std::cout,
            boost::log::keywords::format = COMMON_FMT,
            boost::log::keywords::auto_flush = true
        );*/

        // Output message to file, rotates when file reached 1mb or at midnight every day. Each log file
        // is capped at 1mb and total is 20mb
        boost::log::add_file_log(
            boost::log::keywords::file_name = "sample_%3N.log",
            boost::log::keywords::rotation_size = 1 * 1024 * 1024,
            boost::log::keywords::max_size = 20 * 1024 * 1024,
            boost::log::keywords::time_based_rotation = boost::log::sinks::file::rotation_at_time_point(0, 0, 0),
            boost::log::keywords::format = COMMON_FMT,
            boost::log::keywords::auto_flush = true
        );

        boost::log::add_common_attributes();

        // Only output message with INFO or higher severity in Release
#ifndef _DEBUG
        boost::log::core::get()->set_filter(
            boost::log::trivial::severity >= boost::log::trivial::info
        );
#endif

    }

    /*!
    @brief :    Kite Connect is a set of REST-like APIs that expose
                many capabilities required to build a complete
                investment and trading platform. Execute orders in
                real time, manage user portfolio, stream live market
                data (WebSockets), and more, with the simple HTTP API collection

                This module provides an easy to use abstraction over the HTTP APIs.
                The HTTP calls have been converted to methods and their JSON responses are returned.
                See the **[Kite Connect API documentation](https://kite.trade/docs/connect/v3/)**
                for the complete list of APIs, supported parameters and values, and response formats.

                To place order
                std::string route = "order.place";
                std::map < std::string, std::string> details{ 
                    {"variety", kite::VARIETY_REGULAR},
                    {"tradingsymbol", "INFY"},
                    {"exchange",            kite::EXCHANGE_NSE},
                    {"transaction_type",    kite::TRANSACTION_TYPE_BUY},
                    {"quantity",            std::to_string(1)},
                    {"order_type",            kite::ORDER_TYPE_MARKET},
                    {"product",                kite::PRODUCT_NRML},
                };
                kiteInstance.place_order(details) ;
    */
    class KiteConnect
    {
    public:
        enum apiState { PRE_LOGIN, LOGGEDIN, LOGGOUT };

    private:
        std::string api_key;
        std::string access_token;
        std::string root;
        bool debugEnabled;
        cpr::Timeout timeout;
        cpr::Proxies proxies;
        //todo: http pool not implemented
        bool verifySsl;

        // internal
        std::string userId;
        std::string currentUrl;
        std::string kite_version;
        apiState currState;

        std::function<void(void)> session_expiry_hook;

        cpr::Session session;
        // We need two cookies 1. Initial login cookie, 2. after login
        cpr::Cookies cookieJar[LOGGOUT];
        cpr::Header headers;

    public:
        /*!
        @brief : Initialize a new Kite Connect client instance.
        @param apiKey             API Key issued to you
        @param accessToken     The token obtained after the login flow in exchange for the `RequestToken` . 
                                            Pre-login, this will default to None,but once you have obtained it, you should persist it in a database or session to pass 
                                            to the Kite Connect class initialisation for subsequent requests.
        @param rootUrl             API end point root. Unless you explicitly want to send API requests to a non-default endpoint, this can be ignored.
        @param enableDebug    If set to True, will serialise and print requests and responses to stdout.
        @param timeoutValInSec  Time in milliseconds for which  the API client will wait for a request to complete before it fails.
        @param proxySetting        To set proxy for http request. Should be an object of cpr::Proxies.
        @param userdefinedHeader Client supplied http header fields.
        @param disableSSL            Disable SSL ( to bypass certificate check problem ).
        */
        KiteConnect(
            std::string  apiKey,
            std::string  accessToken="",
            std::string  rootUrl="",
            /*HTTP pool*/
            bool enableDebug = false,
            int timeoutValInSec = 0,
            const cpr::Proxies &proxySetting,
            const cpr::Header  &userdefinedHeader,
            /*if enabled, you may face problem in certificate validation in libCurl*/
            bool disableSSL = true
        ) :
            api_key(apiKey),
            access_token(accessToken),
            root( rootUrl.empty() ? _DEFAULT_BASE_URI : rootUrl ),
            proxies(proxySetting),
            // http pool not implemented
            debugEnabled(enableDebug),
            timeout(timeoutValInSec ? cpr::Timeout(timeoutValInSec * 1000) : cpr::Timeout(_default_timeout * 1000)),
            verifySsl( ! disableSSL),
            kite_version("3"),
            headers(userdefinedHeader.empty() ? HEADER : userdefinedHeader)
        {
            // setup
            session.SetProxies(proxies);
            session.SetTimeout(timeout);
            session.SetVerifySsl(cpr::VerifySsl{ verifySsl });
            session.SetLowSpeed(cpr::LowSpeed{ 30, 60 });
            session.SetHeader(headers);
            session.SetRedirect(true);

            // start logging
            init_log();

            if (debugEnabled)
            {
                boost::log::core::get()->set_filter(
                    boost::log::trivial::severity >= boost::log::trivial::debug
                );
            }

            // TODO : change the const var of class so that base/root url modifies them all : use fmt::format
            if ( ! rootUrl.empty())
            {
                root = rootUrl;
                if (root.back() == '/')
                {
                    root.pop_back();
                }
            }

            currState = LOGGOUT;
        };
        
        ~KiteConnect() {};

        /*!
          @brief : Enabling logging prints HTTP request and response summaries to console
          @param enableDebug
         */
        inline void EnableLogging( bool enableDebug )
        {
           debugEnabled = enableDebug;
           if ( debugEnabled )
           {
              boost::log::core::get()->set_filter(
                    boost::log::trivial::severity >= boost::log::trivial::debug
                );
           }
        }
        
        /*!
            @brief : Set a callback hook for session (`TokenError` -- timeout, expiry etc.) errors.
                          An `AccessToken` (login session) can become invalid for a number of
                          reasons, but it doesn't make sense for the client to
                          try and catch it during every API call.
                          A callback method that handles session errors
                          can be set here and when the client encounters
                          a token error at any point, it'll be called.
                          This callback, for instance, can log the user out of the UI,
                          clear session cookies, or initiate a fresh login.
            @param functionPtr : User action to be invoked when session becomes invalid.
        */
        inline void set_session_expiry_hook(std::function<void(void)> functionPtr = nullptr)
        {
            if (nullptr != functionPtr)
                this->session_expiry_hook = functionPtr;
            else
                throw std::invalid_argument("Invalid input type. Only functions are accepted.");
        }

        /*!
            @brief : Set a callback hook for session (`TokenError` -- timeout, expiry etc.) errors.
            @param accessToken : Access token for the session
        */
        inline void SetAccessToken( std::string accessToken)
        {
            this->access_token = accessToken;
        }
        /*!
          @brief Get the remote login url to which a user should be redirected to initiate the login flow.
          @return Login url to authenticate the user.
         */
        inline std::string GetLoginURL()
        {
            return fmt::format(fmt("{:s}?api_key={:s}&v=3"), _DEFAULT_LOGIN_URI, api_key);
        }
        
        /*!
          @brief  Generate user session details like `access_token` etc by exchanging `request_token`.
                      Access token is automatically set if the session is retrieved successfully.
                      Do the token exchange with the `request_token` obtained after the login flow,
                      and retrieve the `access_token` required for all subsequent requests. The
                      response contains not just the `access_token`, but metadata for
                      the user who has authenticated.
          @param  requestToken  is the token obtained from the GET paramers after a successful login redirect.
          @param  appSecret       is the API api_secret issued with the API key.
          @return User structure with tokens and profile data
                        error: { 'status' : 'error'  }
          */
        inline json& generateSession(std::string requestToken, std::string appSecret)
        {
            static json result = json({}); // object
            result.clear();
            // calculate SHA256 using openSSL api
            uint8_t checksum[EVP_MAX_MD_SIZE];
            std::string input = this->api_key + requestToken + appSecret;
            int length = util::sha256( &checksum, input );
            if ( length == -1 )
            {
                result["status"] = "error";
                return result;
            }
            
            // post
            std::map<std::string, std::string> param;
            util::addIfNotNull(param,"api_key",this->api_key);
            util::addIfNotNull(param,"request_token",requestToken);
            util::addIfNotNull(param,"checksum",std::string( *checksum, length ));
            _POST("api.token", param, result, false);
            
            return result;
        }
        
        /*!
          @brief  Kill the session by invalidating the access token
          @param  accessToken  Access token to invalidate. Default is the active access token..
          @param  appSecret       is the API api_secret issued with the API key.
          @return User structure with tokens and profile data
                        error: { 'status' : 'error'  }
          */
        inline json& invalidateAccessToken(std::string accessToken="")
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() )
            {
              result["status"] = "error";
              return result;
            }
            std::map<std::string, std::string> param;
            util::addIfNotNull(param,"api_key",this->api_key);
            util::addIfNotNull(param,"access_token", accessToken.empty() ? this->access_token : accessToken );
            
            _DELETE("api.token",param, result, false);
            return result;
        }

        /*!
          @brief  Invalidates RefreshToken.
          @param  refreshToken  RefreshToken to invalidate.
          @return User structure with token
                        error: { 'status' : 'error'  }
        */
        inline json& invalidateRefreshToken( std::string refreshToken )
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() )
            {
              result["status"] = "error";
              return result;
            }
            
            std::map<std::string, std::string> param;
            util::addIfNotNull(param,"api_key",this->api_key);
            util::addIfNotNull(param,"refresh_token", refreshToken);
            
            _DELETE("api.token",param, result, false);
            return result;
        }

        /*!
          @brief  Renew AccessToken using RefreshToken.
          @param  refreshToken  RefreshToken to renew the AccessToken.
          @param  appSecret       is the API api_secret issued with the API key.
          @return User structure with TokenRenewResponse that contains new AccessToken and RefreshToken.
                        error: { 'status' : 'error'  }
        */
        inline json& renewAccessToken( std::string refreshToken, std::string appSecret )
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() )
            {
              result["status"] = "error";
              return result;
            }
            
            // calculate SHA256 using openSSL api
            uint8_t checksum[EVP_MAX_MD_SIZE];
            std::string input = this->api_key + refreshToken + appSecret;
            int length = util::sha256( &checksum, input );
            if ( length == -1 )
            {
                result["status"] = "error";
                return result;
            }
            
            // post
            std::map<std::string, std::string> param;
            util::addIfNotNull(param,"api_key", this->api_key);
            util::addIfNotNull(param,"refresh_token", requestToken);
            util::addIfNotNull(param,"checksum",std::string( *checksum, length ));
            
            _POST("api.refresh", param, result, false);
            return result;
        }
        
        /*!
          @brief  Gets currently logged in user details.
          @return User structure with User profile
                        error: { 'status' : 'error'  }
        */
        inline json& getProfile()
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() )
            {
              result["status"] = "error";
              return result;
            }
            
            std::map<std::string, std::string> param;
            _GET("user.profile",param,result);
            return result;
        }

        /*!
          @brief  Get account balance and cash margin details for all segments.
          @return User structure with User margin response with both equity and commodity margins.
                        error: { 'status' : 'error'  }
        */
        inline json& getMargins()
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() )
            {
              result["status"] = "error";
              return result;
            }
            
            std::map<std::string, std::string> param;
            _GET("user.margins",param,result);
            return result;
        }
        
        /*!
          @brief  Get account balance and cash margin details for a particular segment.
          @param segment Trading segment (eg: equity or commodity)
          @return User structure with User margin response with both equity and commodity margins.
                        error: { 'status' : 'error'  }
        */
        inline json& getMargins(std::string segment)
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() )
            {
              result["status"] = "error";
              return result;
            }
            
            std::map<std::string, std::string> param;
            util::addIfNotNull(param, "segment", segment );
            _GET("user.segment_margins",param,result);
            return result;
        }
        
        /*!
        @brief    Place an order.
        @param Exchange Name of the exchange.
        @param TradingSymbol Tradingsymbol of the instrument.
        @param TransactionType BUY or SELL.
        @param Quantity Quantity to transact.
        @param Price For LIMIT orders.
        @param Product Margin product applied to the order (margin is blocked based on this). Default : CNC cash-n-carry.
        @param OrderType Order type (MARKET, LIMIT etc.). Default : MARKET.
        @param Validity Order validity. Default DAY.
        @param DisclosedQuantity Quantity to disclose publicly (for equity trades).
        @param TriggerPrice For SL, SL-M etc..
        @param SquareOffValue Price difference at which the order should be squared off and
                      profit booked (eg: Order price is 100. Profit target is 102. So squareoff = 2).
        @param StoplossValue Stoploss difference at which the order should be squared off
                      (eg: Order price is 100. Stoploss target is 98. So stoploss = 2).
        @param TrailingStoploss Incremental value by which stoploss price changes when market moves
                      in your favor by the same incremental value from the entry price (optional).
        @param Variety You can place orders of varieties; regular orders, after market orders, cover orders etc. .
                      Default VARIETY_REGULAR.
        @param Tag An optional tag to apply to an order to identify it (alphanumeric, max 8 chars).
        @return Json response in the form of nested string dictionary.
                        error: { 'status' : 'error'  }
        */
        inline json& placeOrder(
            std::string Exchange,
            std::string TradingSymbol,
            std::string TransactionType,
            int Quantity = 0,
            double Price = 0.0,
            std::string Product = PRODUCT_CNC,
            std::string OrderType = ORDER_TYPE_MARKET,
            std::string Validity = VALIDITY_DAY,
            int DisclosedQuantity = 0,
            double TriggerPrice = 0.0,
            double SquareOffValue = 0.0,
            double StoplossValue = 0.0,
            double TrailingStoploss = 0.0,
            std::string Variety = VARIETY_REGULAR,
            std::string Tag = "")
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() )
            {
              result["status"] = "error";
              return result;
            }
            
            if ( Exchange.empty() || TradingSymbol.empty() || TransactionType.empty() || Quantity == 0 )
            {
              result["status"] = "error";
              return result;
            }
            
            std::map<std::string, std::string> param;
            util::addIfNotNull(param, "exchange", Exchange);
            util::addIfNotNull(param, "tradingsymbol", TradingSymbol);
            util::addIfNotNull(param, "transaction_type", TransactionType);
            util::addIfNotNull(param, "quantity", Quantity);
            
            util::addIfNotNull(param, "price", Price);
            util::addIfNotNull(param, "product", Product);
            util::addIfNotNull(param, "order_type", OrderType);
            util::addIfNotNull(param, "validity", Validity);
            util::addIfNotNull(param, "disclosed_quantity", DisclosedQuantity);
            util::addIfNotNull(param, "trigger_price", TriggerPrice);
            util::addIfNotNull(param, "squareoff", SquareOffValue);
            util::addIfNotNull(param, "stoploss", StoplossValue);
            util::addIfNotNull(param, "trailing_stoploss", TrailingStoploss);
            util::addIfNotNull(param, "variety", Variety);
            util::addIfNotNull(param, "tag", Tag);

            _POST("orders.place",param,result);
            return result;
        }
                
        /*!
        @brief    Modify an open order.
        @param OrderId Id of the order to be modified.
        @param ParentOrderId Id of the parent order (obtained from the /orders call) as BO is a multi-legged order.
        @param Exchange Name of the exchange.
        @param TradingSymbol Tradingsymbol of the instrument.
        @param TransactionType BUY or SELL.
        @param Quantity Quantity to transact.
        @param Price For LIMIT orders.
        @param Product Margin product applied to the order (margin is blocked based on this).
        @param OrderType Order type (MARKET, LIMIT etc.).
        @param Validity Order validity.
        @param DisclosedQuantity Quantity to disclose publicly (for equity trades).
        @param TriggerPrice For SL, SL-M etc..
        @param Variety You can place orders of varieties; regular orders, after market orders, cover orders etc. .
        @return Json response in the form of nested string dictionary.
                        error: { 'status' : 'error'  }
        */
        inline json& modifyOrder(
            std::string OrderId,
            std::string ParentOrderId = "",
            std::string Exchange ="",
            std::string TradingSymbol ="",
            std::string TransactionType ="",
            int Quantity = 0,
            double Price = 0.0,
            std::string Product = PRODUCT_CNC,
            std::string OrderType = ORDER_TYPE_MARKET,
            std::string Validity = VALIDITY_DAY,
            int DisclosedQuantity = 0,
            double TriggerPrice = 0.0,
            std::string Variety = VARIETY_REGULAR)
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() || OrderId.empty() )
            {
              result["status"] = "error";
              return result;
            }
            
            if ( (Product == PRODUCT_BO || Product == PRODUCT_CO) &&
                  false == util::CaseInsensitiveStringCompare(Variety, Product) ) )
            {
                throw InputException(fmt::format(fmt("Invalid variety. It should be: \"{:s}\""), Product));
            }
            
            std::map<std::string, std::string> param;
            util::addIfNotNull(param, "order_id", OrderId);
            util::addIfNotNull(param, "parent_order_id", ParentOrderId);
            util::addIfNotNull(param, "trigger_price", TriggerPrice);
            util::addIfNotNull(param, "variety", Variety);
            
            if ( Variety == VARIETY_BO && Product == PRODUCT_BO  )
            {
              util::addIfNotNull(param, "quantity", Quantity);
              util::addIfNotNull(param, "price", Price);
              util::addIfNotNull(param, "disclosed_quantity", DisclosedQuantity);
            }
            else if ( Variety == VARIETY_CO && Product == PRODUCT_CO  )
            {
              util::addIfNotNull(param, "exchange", Exchange);
              util::addIfNotNull(param, "tradingsymbol", TradingSymbol);
              util::addIfNotNull(param, "transaction_type", TransactionType);
              util::addIfNotNull(param, "quantity", Quantity);
              util::addIfNotNull(param, "price", Price);
              util::addIfNotNull(param, "product", Product);
              util::addIfNotNull(param, "order_type", OrderType);
              util::addIfNotNull(param, "validity", Validity);
              util::addIfNotNull(param, "disclosed_quantity", DisclosedQuantity);
            }

            _POST("orders.modify",param,result);
            return result;
        }
        
        /*!
        @brief    Cancel an order.
        @param OrderId Id of the order to be modified.
        @param ParentOrderId Id of the parent order (obtained from the /orders call) as BO is a multi-legged order.
        @param Variety You can place orders of varieties; regular orders, after market orders, cover orders etc. .
        @return Json response in the form of nested string dictionary.
                        error: { 'status' : 'error'  }
        */
        inline json& modifyOrder(
            std::string OrderId,
            std::string ParentOrderId = "",
            std::string Variety = VARIETY_REGULAR)
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() || OrderId.empty() )
            {
              result["status"] = "error";
              return result;
            }

            std::map<std::string, std::string> param;
            util::addIfNotNull(param, "order_id", OrderId);
            util::addIfNotNull(param, "parent_order_id", ParentOrderId);
            util::addIfNotNull(param, "variety", Variety);
            
            _DELETE("orders.cancel",param,result);
            return result;
        }
        
        /*!
        @brief    Gets the collection of orders from the orderbook.
        @return Json response in the form of nested string dictionary.
                        error: { 'status' : 'error'  }
        */
        inline json& getOrders( )
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() || OrderId.empty() )
            {
              result["status"] = "error";
              return result;
            }

            std::map<std::string, std::string> param;            
            _GET("orders",param,result);
            return result;
        }
        
        /*!
        @brief    Gets the collection of orders from the orderbook.
        @return Json response in the form of nested string dictionary.
                        error: { 'status' : 'error'  }
        */
        inline json& getOrderHistory( std::string orderId )
        {
            static json result = json({}); // object
            result.clear();
            
            if ( this->api_key.empty() || OrderId.empty() )
            {
              result["status"] = "error";
              return result;
            }

            std::map<std::string, std::string> param;
            param["order_id"] = orderId;
            _GET("orders",param,result);
            return result;
        }
        
////////////////////////////////////
///// PRIVATE FUNCTIONS  /////
////////////////////////////////////
    private:

        /*!
        @brief Create url from input map of route & patterns
                   boost::regex with boost::sregex_token_iterator could replace all this code.
        @param route : will use this as key to _route to get url pattern
        @param patternMap : Map of parameters for request, will pop keys matching url pattern
        @return completed URL
        */
        std::string _create_url( std::string route,
                                          std::map<std::string, std::string>  patternMap)
        {
            auto url_p = _routes.find(route);
            if (url_p == _routes.end() || url_p->second.empty())
                throw InputException(fmt::format(fmt("Unknown route : \"{:s}\""), route));

            const std::string &patternStr = url_p->second;

            BOOST_LOG_TRIVIAL(debug)
                << fmt::format("{:s}", __func__)
                << fmt::format(fmt("\n \"URL Pattern\" is {:s} "), patternStr)
                ;

            std::string url;
            url.reserve(patternStr.length());

            // USER DEFINED PARSER for '{' & '}' tokens
            // 2 case :
            // a. no '{' '}' pair exist
            // b. pair of '{' '}' exist, cannot be without pairs
            
            std::size_t tok_1_Pos { 0 }, tok_2_Pos{ 0 };
            // assume that position zero char is } (tok_2_Pos), we will copy from there to tok_1_Pos

            auto wrongPattern = [](char e, char g) { 
                throw InputException(fmt::format("Expected \'{:c}\' , got \'{:c}\'",e, g));
            };

            unsigned char nextExpectedPattern = '{';
            int count = 0;
            for (unsigned int idx = 0; idx < patternStr.length(); idx++)
            {
                switch (patternStr[idx])
                { 
                case '{':
                {
                    if (count == 1)
                    {
                        wrongPattern('}', '{');
                    }
                    count++;
                    tok_1_Pos = idx;
                    // copy from prev '}' or zero to here is done at default case
                    BOOST_LOG_TRIVIAL(debug)
                        << fmt::format(fmt(" case FIRST \"URL constructed till now\" is \"{:s}\" "), url);
                }
                break;

                case '}':
                {
                    if (count == 0)
                    {
                        wrongPattern('{', '}');
                    }
                    count--;
                    tok_2_Pos = idx;

                    auto strSize = tok_2_Pos - tok_1_Pos - 1;
                    auto key ( patternStr.substr( tok_1_Pos + 1, strSize ) );

                    BOOST_LOG_TRIVIAL(debug)
                        << fmt::format(fmt(" case SECOND "))
                        << fmt::format(fmt("\n \"patternStr\" pos1:{:d} pos2:{:d} substr \"{:s}\" "), tok_1_Pos + 1, tok_2_Pos - 1 , key);
                    
                    if (key.empty())
                        throw InputException(fmt::format("Empty \"pattern\" String in Lib route map \"{:s}\"", patternStr));
                    
                    // get pattern for 'key'
                    if (!patternMap.count(key))
                        throw InputException(fmt::format("Missing key \"{:s}\" in Userinput map", key));
                    
                    BOOST_LOG_TRIVIAL(debug)
                        << fmt::format(fmt("\n \"URL constructed till now\" is \"{:s}\" "), url)
                        << fmt::format(fmt("\n userInput patternMap Value : \"{:s}\""), patternMap.at(key));
                    
                    url.append(patternMap.at(key));
                    patternMap.erase(key);
                }
                break;

                default:
                {
                    if (count == 0)
                        url.append( &patternStr.at(idx), 1 );
                }
                break;

                }
            }

            if ( count != 0 )
                throw InputException(fmt::format("Missing token \"{:c}\" in library route map for route \"{:s}\"",
                (count > 0 ? '{' : '}' ), route));

            url.insert(0, root);
            BOOST_LOG_TRIVIAL(debug) << "Finally " << __FUNCTION__ << " URL : " <<url;
            return url;
        }

        //////////////////////////////////////////////////////
        //////        CONNECTION PRIVATE FUNCTION            //////
        //////////////////////////////////////////////////////

        void addExtraHeaders(const std::string &route,
                                          cpr::Header &passedHeader)
        {
            passedHeader.insert_or_assign("origin","https://kite.zerodha.com");
            passedHeader.insert_or_assign("X-Kite-Version", kite_version);
            passedHeader.insert_or_assign("Authorization", "token "+api_key+":"+access_token);
            passedHeader.insert_or_assign("Referer", "https://kite.zerodha.com/dashboard");
        }

        /// @brief common session setter
        void _setSessionParams(    const httpReq &verb,
                                const std::string route,
                                std::map<std::string, std::string>  &details,
                                std::string overRideURL = "")
        {
            // 1. set headers
            cpr::Header reqHeader = HEADER; // a copy

            BOOST_LOG_TRIVIAL(debug) << "Before modification Headers";
            for (auto &h : reqHeader)
                BOOST_LOG_TRIVIAL(debug) << fmt::format("{} : {}",h.first,h.second);
            addExtraHeaders(route, reqHeader);
            BOOST_LOG_TRIVIAL(debug) << "After modification Headers";
            for (auto &h : reqHeader)
                BOOST_LOG_TRIVIAL(debug) << fmt::format("{} : {}", h.first, h.second);
            session.SetHeader(reqHeader);
            // 2. set cookies
            session.SetCookies(cookieJar[currState]);
            // 3. create url : will consume details
            auto url = overRideURL;
            if (url.empty())
                url = _create_url(route, details);
            session.SetUrl(url);

            // 4. set parameters / payload / body
            cpr::Parameters params{};
            cpr::Payload payload{};
            cpr::Body body{};

            std::string debugParamStr;

            if (verb == GET || verb == DELETE)
            {
                for (auto &p : details)
                    params.AddParameter(cpr::Parameter(p.first, p.second));
                debugParamStr = (params.content.length() ? params.content : "None");
                session.SetParameters(params);
            }
            else if (verb == POST)
            {
                for (auto &p : details)
                    payload.AddPair(cpr::Pair(p.first, p.second));
                debugParamStr = (payload.content.length() ? payload.content : "None");
                //body.assign(payload.content);
                //session.SetBody(body);
                session.SetPayload(payload);
                //url.append("?"+ payload.content);

                reqHeader.insert_or_assign("content-type", "application/x-www-form-urlencoded");
                reqHeader.insert_or_assign("content-length", std::to_string( payload.content.length() ) );
                session.SetHeader(reqHeader);
            }
            else if (verb == PUT )
            {
                for (auto &p : details)
                    payload.AddPair(cpr::Pair(p.first, p.second));
                debugParamStr = (payload.content.length() ? payload.content : "None");
                session.SetPayload(payload);
            }


            if (debugEnabled) // this is here to reduce scope
            {
                fmt::memory_buffer headerBuf;
                auto headerPrinter = [&](auto pair) {format_to(headerBuf, "{} :\t{}\n", pair.first, pair.second); };
                std::for_each(reqHeader.begin(), reqHeader.end(), headerPrinter);

                BOOST_LOG_TRIVIAL(debug) <<
                    fmt::format(fmt(
                        "\n-------------------------------------"
                        "\nREQUEST"
                        "\n-------------------------------------"
                        "\nmethod               : {}"
                        "\nURL                  : {}"
                        "\nparams/body/payload  : {}"
                        "\nheaders              : {}"
                        "\ncookie               : {}"
                        "\n-------------------------------------\n"
                    ),
                        httpVerbMap.at(verb),
                        url,
                        debugParamStr,
                        to_string(headerBuf),
                        cookieJar[currState].GetEncoded());
            }

        }

        /*!
        @brief GET request
        @param route  [in]  : Set by requester , it is the key of predefined _routes map
        @param result [out] : json result
        @param saveResultCookie [in] : defaults to false, if true then saves response cookie in index of "currState"
        */
        void _GET(  const std::string route,
                          std::map<std::string, std::string>  &details,
                          json &result,
                          bool saveResultCookie = false)
        {
            _setSessionParams(GET, route, details);
            _request(GET, result, saveResultCookie);
        }

        /*!
            @brief DELETE request
            @param route  [in]  : Set by requester , it is the key of predefined _routes map
            @param result [out] : json result
            @param saveResultCookie [in] : defaults to false, if true then saves response cookie in index of "currState"
        */
        void _DELETE(  const std::string route,
                              std::map<std::string, std::string>  &details,
                              json &result,
                              bool saveResultCookie = false)
        {
            _setSessionParams(DELETE, route, details);
            _request(DELETE, result, saveResultCookie);
        }

        /*!
            @brief PUT request
            @param route  [in]  : Set by requester , it is the key of predefined _routes map
            @param result [out] : json result
            @param saveResultCookie [in] : defaults to false, if true then saves response cookie in index of "currState"
        */
        void _PUT( const std::string route,
                        std::map<std::string, std::string>  &details,
                        json &result,
                        bool saveResultCookie = false)
        {
            _setSessionParams(PUT, route, details);
            _request(PUT, result, saveResultCookie);
        }

        /*!
            @brief POST request
            @param route  [in]  : Set by requester , it is the key of predefined _routes map
            @param result [out] : json result
            @param saveResultCookie [in] : defaults to false, if true then saves response cookie in index of "currState"
        */
        void _POST( const std::string route,
                          std::map<std::string, std::string>  &details,
                          json &result,
                          bool saveResultCookie = false)
        {
            _setSessionParams(POST, route, details);
            _request(POST, result, saveResultCookie);
        }


        void _request(httpReq verb, json &result, bool saveResultCookie=false )
        {
            if (result.type() != json::value_t::object)
            {
                throw InputException(fmt::format("Result json should be of \"object\" type instead type is {:s}", result.type_name()));
            }
            result.clear();

            cpr::Response resp;
            try
            {
                switch (verb)
                {
                case GET:
                    resp = session.Get();
                    break;
                case DELETE:
                    resp = session.Delete();
                    break;
                case PUT:
                    resp = session.Put();
                    break;
                case POST:
                    resp = session.Post();
                    break;
                }
            }
            catch (const std::runtime_error& re)
            {
                // speciffic handling for runtime_error
                BOOST_LOG_TRIVIAL(fatal)
                    << "Web session generated a runtime exception \""
                    << re.what() << "\"";
                throw;
            }
            catch (const std::exception& ex)
            {
                // speciffic handling for all exceptions extending std::exception, except
                // std::runtime_error which is handled explicitly
                BOOST_LOG_TRIVIAL(fatal)
                    << "Web session generated a exception \""
                    << ex.what() << "\"";
                throw;
            }
            catch (...)
            {
                // catch any other errors (that we have no information about)
                BOOST_LOG_TRIVIAL(fatal)
                    << "Web session generated a UNEXCEPTED exception !!";
                throw;
            }

            if(debugEnabled) // this is here to reduce scope
            {
                fmt::memory_buffer headerBuf;
                auto headerPrinter = [&](auto pair) {format_to(headerBuf, "{} :\t{}\n", pair.first, pair.second); };
                std::for_each(resp.header.begin(), resp.header.end(), headerPrinter);

                int contentCharLimit = resp.text.length() > 60 ? 60 : resp.text.length();

                BOOST_LOG_TRIVIAL(debug) <<
                    fmt::format(fmt(
                        "\n-------------------------------------"
                        "\nRESPONSE"
                        "\n-------------------------------------"
                        "\nStatus code  : {}"
                        "\nError code   : {}\n"
                        "\nHeaders      : {}"
                        "\nCookie       : {}"
                        "\nContent      : {}"
                        "\nError msg    : {}"
                        "\n-------------------------------------\n"),
                        resp.status_code,
                        int(resp.error.code),
                        to_string(headerBuf),
                        resp.cookies.GetEncoded(),
                        resp.text.substr(0, contentCharLimit),
                        resp.error.message
                    );
            }

            if (resp.error) // curl api problem or user env (like ssl or proxy) problem
            {
                throw DataException(fmt::format("Session lib error \n error code :{:d}\n error message :{:s}",
                                                 int(resp.error.code),resp.error.message));
            }

            CaseInsensitiveStringFind compareCaseInsensitiveString;
            json json = json::object();
            if (compareCaseInsensitiveString(resp.header["Content-Type"], std::string("application/json")))
            {
                try
                {
                    json = json::parse(resp.text);
                }
                catch (const std::runtime_error& re)
                {
                    // speciffic handling for runtime_error
                    BOOST_LOG_TRIVIAL(fatal)
                        << "JSON parsing generated a exception \""
                        << re.what() << "\"";
                    throw;
                }
                catch (const json::exception &jsonEx)
                {
                    // speciffic handling for nlohmann::json::exception
                    BOOST_LOG_TRIVIAL(fatal)
                        << "JSON parsing generated a exception \""
                        << jsonEx.what() << "\"";
                    throw;
                }
                catch (...)
                {
                    // catch any other errors (that we have no information about)
                    BOOST_LOG_TRIVIAL(fatal)
                        << "JSON parsing generated a UNEXPECTED exception !!";
                    throw;
                }

                if (debugEnabled)
                    BOOST_LOG_TRIVIAL(debug)
                    << "\n----------------"
                    << "\n   JSON DUMP"
                    << "\n Json type : " << json.type_name()
                    << "\n----------------\n"
                    << json.dump(4)
                    << std::endl;

                // api error
                if (json.find("error_type") != json.end())
                {
                    BOOST_LOG_TRIVIAL(info) << "Got JSON Error";
                    std::string error_type = json.value("error_type", "" );
                    std::string error_message = json.value("message", "" );
                    
                    if ( error_type.find("GeneralException") != std::string::npos )
                    {
                        BOOST_LOG_TRIVIAL(fatal) << fmt::format("{} Error : {} , msg : {}", "GeneralException",error_message, resp.status_code);
                        throw GeneralException(error_message,resp.status_code);
                    }
                    else if (error_type.find("TokenException") != std::string::npos)
                    {
                        if (session_expiry_hook != nullptr)
                        {
                            session_expiry_hook();
                        }
                        BOOST_LOG_TRIVIAL(fatal) << fmt::format("{} Error : {} , msg : {}", "TokenException", error_message, resp.status_code);
                        throw TokenException(error_message, resp.status_code);
                    }
                    else if (error_type.find("PermissionException") != std::string::npos)
                    {
                        BOOST_LOG_TRIVIAL(fatal) << fmt::format("{} Error : {} , msg : {}", "PermissionException", error_message, resp.status_code);
                        throw PermissionException(error_message, resp.status_code);
                    }
                    else if (error_type.find("OrderException") != std::string::npos)
                    {
                        BOOST_LOG_TRIVIAL(fatal) << fmt::format("{} Error : {} , msg : {}", "OrderException", error_message, resp.status_code);
                        throw OrderException(error_message, resp.status_code);
                    }
                    else if (error_type.find("InputException") != std::string::npos)
                    {
                        BOOST_LOG_TRIVIAL(fatal) << fmt::format("{} Error : {} , msg : {}", "InputException", error_message, resp.status_code);
                        throw InputException(error_message, resp.status_code);
                    }
                    else if (error_type.find("DataException") != std::string::npos)
                    {
                        BOOST_LOG_TRIVIAL(fatal) << fmt::format("{} Error : {} , msg : {}", "DataException", error_message, resp.status_code);
                        throw DataException(error_message, resp.status_code);
                    }
                    else if (error_type.find("NetworkException") != std::string::npos)
                    {
                        BOOST_LOG_TRIVIAL(fatal) << fmt::format("{} Error : {} , msg : {}", "NetworkException", error_message, resp.status_code);
                        throw NetworkException(error_message, resp.status_code);
                    }
                    else
                    {
                        BOOST_LOG_TRIVIAL(fatal) << fmt::format("{} Error : {} , msg : {}", "Unknown GeneralException", error_message, resp.status_code);
                        throw GeneralException(error_message, resp.status_code);
                    }

                }

                result = json::object_t::value_type("result",json);
            }
            //
            //std::vector<kite::csvParse::Row> result = kite::csvParse::csvParse(resp.text.c_str(), resp.text.length());
            //for (size_t r = 0; r < result.size(); r++) {
            //    kite::csvParse::Row& row = result[r];
            //    for (size_t c = 0; c < row.size() - 1; c++) {
            //        std::cout << row[c] << "\t";
            //    }
            //    std::cout << row.back() << std::endl;
            //}
            else if (compareCaseInsensitiveString(resp.header["Content-Type"], std::string("csv")) ||
                     compareCaseInsensitiveString(resp.header["Content-Type"], std::string("text/html")) ||
                     compareCaseInsensitiveString(resp.header["Content-Type"], std::string("application/javascript")))
            {
                BOOST_LOG_TRIVIAL(debug) << "Content - Type is " << resp.header["Content - Type"];
                result.push_back(json::object_t::value_type("result", resp.text));
            }
            else
            {
                result += json::object_t::value_type("result", ""); // worthless for us !!!
                throw DataException(
                    "Unknown Content-Type ({content_type}) with response: ({content})"_format(
                        "content_type"_a = resp.header["Content-Type"],
                        "content"_a = resp.text)
                );
            }

            if (saveResultCookie)
            {
                cookieJar[currState] = resp.cookies;
            }
        }
    };

}
