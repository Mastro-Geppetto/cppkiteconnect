# Find the Gold linker (if available)
#
# GOLD_FOUND    - True if the ld.gold binary is found
# GOLD_CMD      - Path to the ld.gold binary
# GOLD_CXX_FLAG - Compiler flag to set to use gold for linking

# Find the Gold linker binary
FIND_PROGRAM(GOLD_CMD NAMES ld.gold)

INCLUDE(FindPackageHandleStandardArgs)
FIND_PACKAGE_HANDLE_STANDARD_ARGS(GOLD DEFAULT_MSG GOLD_CMD)

if (GOLD_FOUND)
  set(GOLD_CXX_FLAG "-fuse-ld=gold")
endif()

