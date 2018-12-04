#include <iostream>
#include <string>
#include <cpr/cpr.h>
#include <KiteConnect.h>

int main()
{
   std::string  myApiKey;
   std::string  RequestToken;
   std::string  MySecret;
   std::string  rootUrl;
   cpr::Proxies proxySetting;
   cpr::Header  userdefinedHeader;
   bool enableDebug = true;

   try {
      std::cout << "\n====LOGIN======\n" << std::endl;
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
      std::string MyPublicToken = user.at("result").at("data").at("public_token");

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
      std::cerr << "Runtime error: " << re.what() << std::endl;
   }
   catch (const std::exception& ex)
   {
      std::cerr << "Error occurred: " << ex.what() << std::endl;
   }
   catch (...)
   {
      std::cerr << "\nGot Exception\n";
   }

   return 1;
}
