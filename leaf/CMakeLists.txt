cmake_minimum_required(VERSION 3.22)

# Firmware version and monotonic sequence (used for downgrade protection).
if(NOT DEFINED ENV{FL_FW_SEQ})
    set(ENV{FL_FW_SEQ} 1)
endif()
if(NOT DEFINED ENV{FL_FW_VERSION})
    set(ENV{FL_FW_VERSION} "0.1.$ENV{FL_FW_SEQ}")
endif()
set(PROJECT_VER "$ENV{FL_FW_VERSION}")

# The ESP32-S3 target needs the ESP-IDF Bluetooth component (components/bt,
# with its controller library and NimBLE host submodules) for the sensing
# module link. The minimal install in docs/MINIMAL-SETUP.md omits it: add it
# to that tree before building the S3 target.
include($ENV{IDF_PATH}/tools/cmake/project.cmake)
# Build only what main needs: Wi-Fi station and lwip for the outbound link, no listeners.
set(COMPONENTS main)
project(furcate-leaf)

idf_build_set_property(COMPILE_DEFINITIONS "FL_FW_SEQ=$ENV{FL_FW_SEQ}" APPEND)
idf_build_set_property(COMPILE_DEFINITIONS "FL_FW_VERSION=\"$ENV{FL_FW_VERSION}\"" APPEND)
if(DEFINED ENV{FL_ONESHOT_S5B})
    idf_build_set_property(COMPILE_DEFINITIONS "FL_ONESHOT_S5B=1" APPEND)
endif()
if(DEFINED ENV{FL_SELFTEST_FAIL})
    idf_build_set_property(COMPILE_DEFINITIONS "FL_SELFTEST_FAIL=1" APPEND)
endif()
