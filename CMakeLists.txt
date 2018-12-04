#
# Copyright(c) 2018 Promit Chatterjee.
# Distributed under the MIT License (http://opensource.org/licenses/MIT)
#

cmake_minimum_required(VERSION 3.1)

# Determine if this is built as a subproject (using add_subdirectory)
# or if it is the master project.
set(MASTER_PROJECT OFF)
if (CMAKE_CURRENT_SOURCE_DIR STREQUAL CMAKE_SOURCE_DIR)
  set(MASTER_PROJECT ON)
  message(STATUS "CMake version: ${CMAKE_VERSION}")
endif ()

#-------------------------------------------------------------
# vcpkg specific
# user can also give manually "-DCMAKE_TOOLCHAIN_FILE=/USER_PATH_TO/vcpkg/scripts/buildsystems/vcpkg.cmake"
if(DEFINED ENV{VCPKG_ROOT} AND NOT DEFINED CMAKE_TOOLCHAIN_FILE)
  message("VCPKG_ROOT: ${VCPKG_ROOT}") 
  set(CMAKE_TOOLCHAIN_FILE "${VCPKG_ROOT}/scripts/buildsystems/vcpkg.cmake"
      CACHE STRING "")
endif()

#====================================================================================
# project start
#====================================================================================
# Get version : todo get it from a file
set(CPPKITE_VERSION "0.3.0")

project(cppkiteconnect VERSION ${CPPKITE_VERSION} LANGUAGES CXX)

include(CMakeDependentOption)
include(GNUInstallDirs)

#-------------------------------------------------------------
# set default build type CMAKE_BUILD_TYPE to Release.
if(NOT CMAKE_BUILD_TYPE)
   set(docstr "Choose the type of build, options are:None(CMAKE_CXX_FLAGS) Debug Release RelWithDebInfo MinSizeRel.")
   set(CMAKE_BUILD_TYPE "Release" CACHE STRING ${docstr} FORCE)
endif()

# Options that control generation of various targets.
option(CPPKITE_WERROR "Halt the compilation with an error on compiler warnings." OFF)

message(" VCPKG install DIR : ${_VCPKG_INSTALLED_DIR}/${VCPKG_TARGET_TRIPLET}")
#---------------------------------------------------
message(STATUS "Build type: " ${CMAKE_BUILD_TYPE})
message(STATUS "Version: ${CPPKITE_VERSION}")
# module path
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} "${CMAKE_CURRENT_SOURCE_DIR}/cmake")

#-------------------------------------
# packages
set(THREADS_PREFER_PTHREAD_FLAG ON)
find_package (Threads REQUIRED)
find_package(GoldLinker)
find_program(iwyu_path NAMES include-what-you-use iwyu)
if(NOT iwyu_path)
    message("Could not find the program include-what-you-use")
else()
    message("include-what-you-use found at ${iwyu_path}")
endif()

#--------------------------------------------------
# compiler config
include(CheckCXXCompilerFlag)
set(CMAKE_CXX_STANDARD 11)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if (CMAKE_CXX_COMPILER_ID MATCHES "GNU")
   set(PEDANTIC_COMPILE_FLAGS -pedantic-errors -Wall -Wextra -pedantic
      -Wold-style-cast -Wundef
      -Wredundant-decls -Wwrite-strings -Wpointer-arith
      -Wcast-qual -Wformat=2 -Wmissing-include-dirs
      -Wcast-align -Wnon-virtual-dtor
      -Wctor-dtor-privacy -Wdisabled-optimization
      -Winvalid-pch -Woverloaded-virtual
      -Wno-ctor-dtor-privacy -Wno-dangling-else
      -Wno-format-nonliteral -Wno-sign-conversion -Wno-shadow)
   if (NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 4.6)
       set(PEDANTIC_COMPILE_FLAGS ${PEDANTIC_COMPILE_FLAGS} -Wnoexcept)
   endif ()
   if (NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 5.0)
      set(PEDANTIC_COMPILE_FLAGS ${PEDANTIC_COMPILE_FLAGS} -Wdouble-promotion
          -Wtrampolines -Wzero-as-null-pointer-constant -Wuseless-cast
          -Wvector-operation-performance -Wsized-deallocation)
   endif ()
   if (NOT CMAKE_CXX_COMPILER_VERSION VERSION_LESS 6.0)
       set(PEDANTIC_COMPILE_FLAGS ${PEDANTIC_COMPILE_FLAGS} -Wshift-overflow=2
           -Wnull-dereference -Wduplicated-cond)
   endif ()
   set(WERROR_FLAG -Werror)
endif ()

if (CMAKE_CXX_COMPILER_ID MATCHES "Clang")
  set(PEDANTIC_COMPILE_FLAGS -Wall -Wextra -pedantic)
  check_cxx_compiler_flag(-Wzero-as-null-pointer-constant HAS_NULLPTR_WARNING)
  if (HAS_NULLPTR_WARNING)
     set(PEDANTIC_COMPILE_FLAGS ${PEDANTIC_COMPILE_FLAGS}
         -Wzero-as-null-pointer-constant)
  endif ()
  set(WERROR_FLAG -Werror)
endif ()

if (MSVC)
  set(PEDANTIC_COMPILE_FLAGS /W3)
  set(WERROR_FLAG /WX)
endif ()

#-------------------------------------
# address sanitizers
include(cmake/sanitizers.cmake)

#-------------------------------------
# library
set(CPPKITE_HEADERS utils.h KiteException.h KiteConnect.h)
add_library(cppkiteconnect INTERFACE)
add_library(cppkiteconnect::cppkiteconnect ALIAS cppkiteconnect)

option(CPPKITE_BUILD_EXAMPLES "Build examples" OFF)

target_include_directories(
   cppkiteconnect
   INTERFACE
   "$<BUILD_INTERFACE:${CMAKE_CURRENT_LIST_DIR}/include>"
   "$<INSTALL_INTERFACE:${CMAKE_INSTALL_INCLUDEDIR}>"
)
set(HEADER_BASE "${CMAKE_CURRENT_SOURCE_DIR}/include")

#------------------------------------
# Check build flags
if(CPPKITE_WERROR)
   target_compile_options(cppkiteconnect PRIVATE ${WERROR_FLAG})
endif()
#---------------------------------------------------------------------------------------
# Install/export targets and files
# set files and directories
message("Project name : ${PROJECT_NAME}")
message("Project install libdir : ${CMAKE_INSTALL_LIBDIR} includeDir : ${CMAKE_INSTALL_INCLUDEDIR}")
set(config_install_dir "${CMAKE_INSTALL_LIBDIR}/cmake/${PROJECT_NAME}")
set(include_install_dir "${CMAKE_INSTALL_INCLUDEDIR}")
set(pkgconfig_install_dir "${CMAKE_INSTALL_LIBDIR}/pkgconfig")
set(version_config "${CMAKE_BINARY_DIR}/${PROJECT_NAME}ConfigVersion.cmake")
set(project_config "${PROJECT_NAME}Config.cmake")
set(pkg_config "${CMAKE_BINARY_DIR}/${PROJECT_NAME}.pc")
set(targets_export_name "${PROJECT_NAME}Targets")
set(namespace "${PROJECT_NAME}::")

# generate package version file
include(CMakePackageConfigHelpers)
write_basic_package_version_file(
    "${version_config}" COMPATIBILITY SameMajorVersion
)

# configure pkg config file
configure_file("cmake/cppkiteconnect.pc.in" "${pkg_config}" @ONLY)

# install targets
install(
    TARGETS cppkiteconnect
    EXPORT "${targets_export_name}"
)

# install headers
install(
    DIRECTORY "${HEADER_BASE}/${PROJECT_NAME}"
    DESTINATION "${include_install_dir}"
)

# install project version file
install(
    FILES "${version_config}"
    DESTINATION "${config_install_dir}"
)

# install pkg config file
install(
    FILES "${pkg_config}"
    DESTINATION "${pkgconfig_install_dir}"
)

# install project config file
install(
    EXPORT "${targets_export_name}"
    NAMESPACE "${namespace}"
    DESTINATION "${config_install_dir}"
    FILE ${project_config}
)

# export build directory config file
export(
    EXPORT ${targets_export_name}
    NAMESPACE "${namespace}"
    FILE ${project_config}
)

# register project in CMake user registry
export(PACKAGE ${PROJECT_NAME})
file(GLOB_RECURSE cppkite_include_SRCS "${HEADER_BASE}/*.h")
add_custom_target(cppkite_headers_for_ide SOURCES ${cppkite_include_SRCS})

# Build example
if(CPPKITE_BUILD_EXAMPLES)
    add_subdirectory(examples)
endif()

