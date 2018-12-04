# Find and set-up the necessary variables for the CPR
#
# This module defines:
#  CPR_INCLUDE_DIRS, where to find cpr/session.h, etc.
#  CPR_LIBRARIES The libraries needed to use cpr
#  CPR_LIBRARY_PATH - The location(directory) of cpr
#  CPR_FOUND, If false, do not try to use cpr.
#
# If you have CPR installed in a non-standard place, you can define
# CPR_PREFIX to tell cmake where it is.
#
message(STATUS "CPR  Prefix: ${CPR_PREFIX}")

find_path(CPR_INCLUDE_DIR
   NAMES cpr.h
   PATH /usr/include /usr/include/cpr /usr/local/include /usr/local/include/cpr
   ${CPR_PREFIX}/include ${CPR_PREFIX}/include/cpr
   )

find_library(CPR_LIBRARY
   NAMES libcpr.a
   PATH /usr/lib /usr/lib64
   ${CPR_PREFIX}/lib ${CPR_PREFIX}/lib64
   )

find_package_handle_standard_args(CPR DEFAULT_MSG
   CPR_INCLUDE_DIR
   CPR_LIBRARY)

# Copy the results to the output variables.
IF(CPR_FOUND)
   SET(CPR_INCLUDE_DIRS ${CPR_INCLUDE_DIR})
   SET(CPR_LIBRARIES    ${CPR_LIBRARY})
   get_filename_component(CPR_LIBRARY_PATH ${CPR_LIBRARY} DIRECTORY)
ELSE(CPR_FOUND)
   SET(CPR_INCLUDE_DIRS)
   SET(CPR_LIBRARIES)
   SET(CPR_LIBRARY_PATH)
ENDIF(CPR_FOUND)

mark_as_advanced(CPR_INCLUDE_DIRS CPR_LIBRARIES CPR_LIBRARY_PATH)
