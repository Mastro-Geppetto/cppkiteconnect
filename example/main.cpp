#include <iostream>
#include <string>
#include <cpr/cpr.h>
#include <KiteConnect.h>

int main()
{
   std::string  apiKey;
   std::string  accessToken;
   std::string  publicToken;
   std::string  rootUrl;
   cpr::Proxies proxySetting;
   cpr::Header  userdefinedHeader;
   bool enableDebug = true;

   try {
      std::cout << "\n====LOGIN======\n" << std::endl;
      kite::KiteConnect client (apiKey,accessToken,rootUrl);
      /*
      json result = client.login("YO7852","ajrpc1036e");
      std::cout << "\n====F2A======\n" << std::endl;
      std::multimap<std::string, std::string> params;
      auto quids = result.at("result").at("data").at("question_ids").get<std::vector<std::string>>();
      auto questions = result.at("result").at("data").at("questions").get<std::vector<std::string>>();

      for (int i = 0; i < quids.size(); i++)
      {
         params.emplace(quids[i],"ajrpc1036e"); // insert answers
      }
      result.clear();
      result = client.f2a(params);
      std::cout << "\nResult\n" << result.dump(4);
      */
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
