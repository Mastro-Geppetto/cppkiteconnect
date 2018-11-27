# cppkiteconnect : under development
Unofficial c++ client for communicating with the [Kite Connect API](https://kite.trade).

It is based on [official zerodha dotnetkiteconnect](https://github.com/zerodhatech/dotnetkiteconnect).

Kite Connect is a set of REST-like APIs that expose many capabilities required to build a complete investment and trading platform. Execute orders in real time, manage user portfolio, stream live market data (WebSockets), and more, with the simple HTTP API collection.

Licensed under the MIT License.

## Documentation
- [Kite Connect HTTP API documentation](https://kite.trade/docs/connect/v3)

## Requirements
- **GCC 4.8.1 or Visual Studio 2017 / 2015 update 3 (on windows)**: c++11 compliant compiler.
### Dependent Libraries
- **fmt**   : [A modern formatting library](https://github.com/fmtlib/fmt/).
- **Boost** : RegRx (csv parsing) & Logging ( i have used 1.67 but a older version should work ).
I plan to remove boost & fmt for [spdlog](https://github.com/gabime/spdlog) and [fast-cpp-csv-parser](https://github.com/ben-strasser/fast-cpp-csv-parser).
- **CPR**   : [C++ Requests](https://github.com/whoshuu/cpr/).
- **nlohmann-json** : [C++11 headers only json parser](https://nlohmann.github.io/json/).

All these can be added (sourced & compiled ) wrt your platform by using [microsoft vcpkg](https://github.com/Microsoft/vcpkg).
You must give it a try.
**Note i have build this code only on windows machine, but it should compile on Linux**

## Installation Using vcpkg : under development
```
```

## API usage

```
```

## Kite ticker usage - websocket [ not yet implemented ]

```
```

# Examples

Check [examples folder](https://github.com/zerodhatech/cppkiteconnect/tree/master/examples) for more examples.

## Run unit tests

```
```
