/*
https://raw.githubusercontent.com/nghttp2/nghttp2/master/COPYING
 */

#pragma once

#include <iostream>
#include <fstream>
#include <string>
#include <map>
#include <functional>
#include <algorithm>
#include <iterator>
#include <regex>

#include <openssl/evp.h>

namespace util
{
  /////////////////////////////////////////////////////////////////////////////////////////////////
  // inspired by <http://blog.korfuri.fr/post/go-defer-in-cpp/>, but our
  // template can take functions returning other than void.
  template <typename F, typename... T> struct Defer {
    Defer(F &&f, T &&... t)
        : f(std::bind(std::forward<F>(f), std::forward<T>(t)...)) {}
    Defer(Defer &&o) noexcept : f(std::move(o.f)) {}
    ~Defer() { f(); }

    using ResultType = typename std::result_of<typename std::decay<F>::type(
        typename std::decay<T>::type...)>::type;
    std::function<ResultType()> f;
  };

  template <typename F, typename... T> Defer<F, T...> defer(F &&f, T &&... t) {
    return Defer<F, T...>(std::forward<F>(f), std::forward<T>(t)...);
  }
  /////////////////////////////////////////////////////////////////////////////////////////////////
  // date UTC format ("2018-11-26T09:15:00+0530") to time struct
  /////////////////////////////////////////////////////////////////////////////////////////////////

  #if !OPENSSL_1_1_API
  namespace
  {
    EVP_MD_CTX *EVP_MD_CTX_new(void)
    {
        return EVP_MD_CTX_create();
    }
    
    void EVP_MD_CTX_free(EVP_MD_CTX *ctx)
    {
        EVP_MD_CTX_destroy(ctx);
    }
    
  } // namespace
  #endif // !OPENSSL_1_1_API

  namespace
  {
      int message_digest(uint8_t *res, const EVP_MD *meth, const std::string &s)
      {
        auto ctx = EVP_MD_CTX_new();
        if (ctx == nullptr)
        {
          return -1;
        }

        auto ctx_deleter = defer(EVP_MD_CTX_free, ctx);
        
        int rv = EVP_DigestInit_ex(ctx, meth, nullptr);
        if (rv != 1)
        {
          return -1;
        }

        rv = EVP_DigestUpdate(ctx, s.c_str(), s.size());
        if (rv != 1)
        {
          return -1;
        }

        unsigned int mdlen = EVP_MD_size(meth);
        rv = EVP_DigestFinal_ex(ctx, res, &mdlen);
        if (rv != 1)
        {
          return -1;
        }
        
        return mdlen;
      }

  } // namespace

  // Computes SHA-256 of |s|, and stores it in |buf|.  This function
  // returns 0 if it succeeds, or -1.
  int sha256(uint8_t *result,  const std::string &inputStr)
  {
    return message_digest(result, EVP_sha256(), inputStr);
  }

  int sha1(uint8_t *result, const std::string &inputStr)
  {
    return message_digest(result, EVP_sha1(), inputStr);
  }

  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  
  /*!
  @brief
  */
  struct CaseInsensitiveStringCompare {
      bool operator()(const std::string& a, const std::string& b) const noexcept
      {
          return std::lexicographical_compare(
              a.begin(), a.end(), b.begin(), b.end(),
              [](unsigned char ac, unsigned char bc) { return std::tolower(ac) < std::tolower(bc); });
      }
  };

  /*!
  @brief
  */
  struct CaseInsensitiveStringFind {
      bool operator()(const std::string& a, const std::string& b) const noexcept
      {
          auto it = std::search(
              a.begin(), a.end(), b.begin(), b.end(),
              [](char ac, char bc) { return std::tolower(ac) == std::tolower(bc); });
          return (it != a.end());
      }
  };
  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  void addIfNotNull( std::multimap<std::string, std::string> &map, const std::string &key, const std::string &value )
  {
    if ( !value.empty() )
    {
        map.emplace(key, value);
    }
  }
  void addIfNotNull( std::multimap<std::string, std::string> &map, const std::string &key, const long double &value )
  {
    if (!value)
    {
        map.emplace( key, std::to_string(value) );
    }
  }
  
  /////////////////////////////////////////////////////////////////////////////////////////////////////////////////
  /*!
  @brief
  */
  namespace csvParse
  {
      // used to split the file in lines
      const std::regex linesregx("\\r\\n|\\n\\r|\\n|\\r");

      // used to split each line to tokens, assuming ',' as column separator
      const std::regex fieldsregx(",(?=(?:[^\"]*\"[^\"]*\")*(?![^\"]*\"))");

      typedef std::vector<std::string> Row;

      std::vector<Row> csvParse(const char* data, unsigned int length)
      {
          std::vector<Row> result;

          // iterator splits data to lines
          std::cregex_token_iterator li(data, data + length, linesregx, -1);
          std::cregex_token_iterator end;

          while (li != end) {
              std::string line = li->str();
              ++li;

              // Split line to tokens
              std::sregex_token_iterator ti(line.begin(), line.end(), fieldsregx, -1);
              std::sregex_token_iterator end2;

              std::vector<std::string> row;
              while (ti != end2) {
                  std::string token = ti->str();
                  ++ti;
                  row.push_back(token);
              }
              if (line.back() == ',') {
                  // last character was a separator
                  row.push_back("");
              }
              result.push_back(row);
          }
          return result;
      }
  } //csvParse
  
} // util
