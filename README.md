# cppkiteconnect
Unofficial headers only c++ client for communicating with the [Kite Connect API](https://kite.trade).

It is based on [official zerodha dotnetkiteconnect](https://github.com/zerodhatech/dotnetkiteconnect).

Kite Connect is a set of REST-like APIs that expose many capabilities required to build a complete investment and trading platform. Execute orders in real time, manage user portfolio, stream live market data (WebSockets), and more, with the simple HTTP API collection.

Licensed under the MIT License.

## Documentation
- [Kite Connect HTTP API documentation](https://kite.trade/docs/connect/v3)

## Requirements
- **GCC 4.9.x (std::regex supported) or Visual Studio 2017 / 2015 update 3 (on windows)**: c++11 compliant compiler.
### Dependent Libraries
- **fmt**   : [A modern formatting library](https://github.com/fmtlib/fmt/).
- **Boost** : boost-regex (csv parsing) & boost-log Logging ( I have used boost 1.67 ). 
I plan to remove boost & fmt for [spdlog](https://github.com/gabime/spdlog) and std::regex for csv-parser.
- **CPR**   : [C++ Requests](https://github.com/whoshuu/cpr/).
- **nlohmann-json** : [C++11 headers only json parser](https://nlohmann.github.io/json/).

All these can be added (sourced & compiled ) wrt your platform by using [Microsoft vcpkg](https://github.com/Microsoft/vcpkg).
You must give it a try.
**Note i have build this code only on windows machine, but it should compile on Linux**

## Installation Using vcpkg 
**On Windows**:
- Install [git](https://git-scm.com/download/win)
- Install [Visual Studio 2017](https://visualstudio.microsoft.com/downloads/)
- Install [vcpkg](https://github.com/Microsoft/vcpkg#quick-start)
  Remember that in this (vcpkg) dir all the libraries will be built,
  so this drive should have sufficient space.
- Open command prompt or powershell prompt and change dir to vcpkg dir
- Install dependent libraries : vcpkg.exe install cpr fmt nlohmann-json boost 
- Git clone or download cppKiteConnect.
- Start a new C++ project in Visual Studio
- Open example directory and build

**On Linux**:
- Install [git](https://git-scm.com/download/linux)
- Install latest gcc.
  - CentOs
    - yum install devtoolset-7-gcc\* libstdc++-static glibc-static
    - scl enable devtoolset-7 bash
  - Ubuntu
    - https://gist.github.com/jlblancoc/99521194aba975286c80f93e47966dc5
- Install dependent libraries
  - CentOs
    - yum install curl fmt boost
    - nlohmann-json : need to [clone and install](https://nlohmann.github.io/json/).
    - CPR : need to [compile and install](https://github.com/whoshuu/cpr#usage).
    - cppKiteConnect : clone git, use the header files present in include.
  - Ubuntu
    - sudo apt-get install curl fmt boost nlohmann-json-dev
    - CPR : need to [compile and install](https://github.com/whoshuu/cpr#usage).
    - cppKiteConnect : clone git, use the header files present in include.
## API usage
```
#include <string>
#include <map>
#include <vector>
#include <iostream>
// Import library
#include <KiteConnect.h>
#include <utils.h>
#include <cpr/cpr.h>

int main()
{
   // define a proxy
   const cpr::Proxies localProxy{
                           {"http", "http://192.168.100.6:8080"},
                           {"https", "http://192.168.100.6:8080"}
   };
   /*
   Connection failure error looks like
   -------------------------------------------------------------------------
   Error occurred: Session libCurl error
   error code :1
   error message :Failed to connect to api.kite.trade.com port 443: Timed out
   -------------------------------------------------------------------------
   */

   std::string  myApiKey      /* = user filled data */;
   std::string  RequestToken  /* = user filled data */;
   std::string  MySecret      /* = user filled data */;


   try {
      // Create a client instance
      // using apiKey. Enabling Debug will give logs of requests and responses
      kite::KiteConnect kite (myApiKey, true,
                              "/*empty access token*/", "/*empty url*/"
                              /*localProxy if required*/);

      // Collect login url to authenticate user. Load this URL in browser or WebView.
      // After successful authentication this will redirect to your redirect url with request token.
      std::string url = kite.GetLoginURL();

      // Collect tokens and user details using the request token
      json user = kite.GenerateSession(RequestToken, MySecret);

      std::string MyAccessToken = user.at("result").at("data").at("access_token");
      std::string MyPublicToken = user.at("result").at("data").at("public
      token");

      // Initialize Kite APIs with access token
      kite.SetAccessToken(MyAccessToken);

      // Set session expiry callback. Method can be separate function also.
      kite.SetSessionExpiryHook( [](){ std::cerr << "\n Need to login again \n"; } );

      // Example call for functions like "GetHoldings"
      json holdings = kite.GetHoldings();
      std::cout << holdings.dump(4) << std::endl; // json dump with 4 space width

      // Example call for functions like "PlaceOrder"
      json response = kite.PlaceOrder(
         kite::EXCHANGE_CDS,
         "USDINR17AUGFUT",
         kite::TRANSACTION_TYPE_SELL,
         1,
         64.0000,
         kite::ORDER_TYPE_MARKET,
         kite::PRODUCT_MIS
      );
      std::cout << std::endl << response.dump(4) << std::endl;
      std::cout << "Order Id: " + response.at("result").at("data").at("order_id").get<std::string>();
   }
   catch (const std::runtime_error& re)
   {
      // speciffic handling for runtime_error
      std::cerr << "Runtime error: " << re.what() << std::endl;
   }
   catch (const std::exception& ex)
   {
      // speciffic handling for all exceptions extending std::exception, except
      // std::runtime_error which is handled explicitly
      std::cerr << "Error occurred: " << ex.what() << std::endl;
   }
   catch (...)
   {
      std::cerr << "\nGot Exception\n";
   }
   return 0;
}
```
## Kite ticker usage - websocket [ not yet implemented ]

```
```

# Examples

Check [examples folder](https://github.com/zerodhatech/cppkiteconnect/tree/master/examples) for more examples.

## Run unit tests

```
```
