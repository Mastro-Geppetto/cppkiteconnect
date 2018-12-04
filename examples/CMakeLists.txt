cmake_minimum_required(VERSION 3.1)
project(cppkiteExamples LANGUAGES CXX)

if(NOT TARGET cppkiteconnect)
   find_package(cppkiteconnect CONFIG REQUIRED)
endif()

include(CheckCXXCompilerFlag)
set(CMAKE_CXX_STANDARD 11 )
set(CMAKE_CXX_STANDARD_REQUIRED ON)
#-------------------------------------
# Build using static libraries
set(BUILD_SHARED_LIBS OFF)
set(CMAKE_FIND_LIBRARY_SUFFIXES ".a")
set(CMAKE_EXE_LINKER_FLAGS ${CMAKE_EXE_LINKER_FLAGS} "-static-libgcc -static-libstdc++")

#------------------------------------
add_executable(cppkiteExamples main.cpp)
#------------------------------------

#------------------------------------
set(CMAKE_BUILD_TYPE "Release")
#------------------------------------
# rest of the packages
set(Boost_USE_STATIC_LIBS ON)
set(Boost_USE_STATIC_RUNTIME ON)
set(Boost_USE_MULTITHREADED ON)
find_package(Boost 1.68 REQUIRED COMPONENTS log log_setup filesystem thread date_time system regex program_options )
message("boost include directory: ${Boost_INCLUDE_DIRS}")
message("boost log library: ${Boost_LOG_LIBRARY}")
message("boost log_setup library: ${Boost_LOG_SETUP_LIBRARY}")
message("boost filesystem library: ${Boost_FILESYSTEM_LIBRARY}")
message("boost thread library: ${Boost_THREAD_LIBRARY}")
message("boost date_time library: ${Boost_DATE_TIME_LIBRARY}")
message("boost system library: ${Boost_SYSTEM_LIBRARY}")
message("boost regex library: ${Boost_REGEX_LIBRARY}")

find_package(ZLIB REQUIRED)
find_package(BZip2 REQUIRED)
#find_package(LibLZMA REQUIRED)
find_package(spdlog CONFIG REQUIRED)
find_package(fmt CONFIG REQUIRED)

#------------ SSL ----------------
if(MSVC)
    target_link_libraries(cppkiteExamples PRIVATE Ws2_32 Wldap32 Crypt32)
    target_compile_options(cppkiteExamples PRIVATE "$<$<CONFIG:Debug>:/MTd>")
    target_compile_options(cppkiteExamples PRIVATE "$<$<CONFIG:Release>:/MT>")
    target_compile_options(cppkiteExamples PRIVATE "$<$<CONFIG:MinSizeRel>:/MT>")
    target_compile_options(cppkiteExamples PRIVATE "$<$<CONFIG:RelWithDebInfo>:/MT>")
else()
    find_package(OpenSSL REQUIRED)
    target_link_libraries(cppkiteExamples PRIVATE OpenSSL::SSL OpenSSL::Crypto)
endif()
#--------------------------------
find_package(CURL REQUIRED)
# CURL vcpkg bug
if (WIN32)
  list(LENGTH CURL_LIBRARY CURL_LIBRARY_LENGTH)
  if (CURL_LIBRARY_LENGTH EQUAL 1)
    set(CURL_LIBRARY_DEBUG_LIB   ${CURL_LIBRARY})
     set(CURL_LIBRARY_RELEASE_LIB ${CURL_LIBRARY_DEBUG_LIB}/../../../lib/libcurl.lib)
      get_filename_component(CURL_LIBRARY_RELEASE_LIB ${CURL_LIBRARY_RELEASE_LIB} REALPATH)
      unset(CURL_LIBRARY CACHE)
      unset(CURL_LIBRARY)
      unset(CURL_LIBRARIES  CACHE)
      unset(CURL_LIBRARIES)
      set(CURL_LIBRARY "debug;${CURL_LIBRARY_DEBUG_LIB};optimized;${CURL_LIBRARY_RELEASE_LIB}")
      set(CURL_LIBRARIES ${CURL_LIBRARY})
  endif()
endif()
#-------------------------------
find_package(CPR REQUIRED)

target_link_libraries(cppkiteExamples PRIVATE fmt::fmt fmt::fmt-header-only
                                             spdlog::spdlog
                                             OpenSSL::SSL OpenSSL::Crypto
                                             ${LIBLZMA_LIBRARIES}
                                             ZLIB::ZLIB
                                             BZip2::BZip2
                                             Threads::Threads
                                             ${CURL_LIBRARIES} 
                                             ${CPR_LIBRARIES}
                                             ${Boost_LIBRARIES}
                                             cppkiteconnect::cppkiteconnect
                     )

target_include_directories(cppkiteExamples PUBLIC ${CMAKE_CURRENT_SOURCE_DIR}
                                                  ${CMAKE_CURRENT_BINARY_DIR}
                                                  ${CURL_INCLUDE_DIRS}
                                                  ${CPR_INCLUDE_DIRS}
                                                  ${Boost_INCLUDE_DIRS}
                                                  ${LIBLZMA_INCLUDE_DIRS}
                                                  ${CMAKE_CURRENT_SOURCE_DIR}../include
                          )
