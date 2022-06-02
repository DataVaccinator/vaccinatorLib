# Copyright DataVaccinator
#
# Permission is hereby granted, free of charge, to any person obtaining a copy
# of this software and associated documentation files (the "Software"), to deal
# in the Software without restriction, including without limitation the rights
# to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
# copies of the Software, and to permit persons to whom the Software is
# furnished to do so, subject to the following conditions:
#
# The above copyright notice and this permission notice shall be included in
# all copies or substantial portions of the Software.
#
# THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
# IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
# FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
# AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
# LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
# OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
# SOFTWARE.

# options
set(VERSION 0.0.1 CACHE STRING "The version")
set(REVISION 0 CACHE STRING "The revision")
set(DEPS_BASE ${CMAKE_INSTALL_PREFIX} CACHE STRING "General dependency installation prefix")
set(MBEDTLS_BASE ${DEPS_BASE} CACHE STRING "Mbed TLS installation prefix")
set(RFUTIL_BASE ${DEPS_BASE} CACHE STRING "regify-util installation prefix")
set(YAJL_BASE ${DEPS_BASE} CACHE STRING "yajl installation prefix")
set(YAJL_LIB "" CACHE STRING "Full path to the yajl library to link against")
set(CURL_BASE ${DEPS_BASE} CACHE STRING "libcurl installation prefix")
set(CURL_LIB "" CACHE STRING "Full path to the cURL library to link against")
option(BUILD_SHARED_LIBS "Whether to build dynamic libraries" ON)
option(INCLUDE_MBEDTLS "Whether to include Mbed TLS statically" ON)
option(INCLUDE_YAJL "Whether to include yajl statically. Do give the full path to the static lib to YAJL_LIB" OFF)
option(INCLUDE_CURL "Whether to include cURL statically. Do give the full paths to the static libs to CURL_LIB" OFF)
option(INSTALL_DEPS "Whether this configuration installs its included dependencies. Used for packaging" OFF)
option(DOCS "Whether to generate the documentation" OFF)
option(TESTING "Whether to build the tests" OFF)
option(SAMPLES "Whether to build the examples" OFF)

# general
cmake_minimum_required(VERSION 3.6)
project(vaccinatorLib
        LANGUAGES C CXX
        VERSION ${VERSION}
        )
set(CMAKE_C_STANDARD 99)
set(NAME vaccinator)
set(staticlib ${NAME}_static)
set(sharedlib ${NAME})
# linker lib version
# Here are a set of rules to help you update your library version information:
# Start with version information of `0.0.0' for each libtool library.
# Update the version information only immediately before a public release of
# your software. More frequent updates are unnecessary, and only guarantee that
# the current interface number gets larger faster.
# If the library source code has changed at all since the last update, then
# increment revision (`c.r.a' becomes `c.r+1.a').
# If any interfaces have been added, removed, or changed since the last update,
# increment current, and set revision to 0.
# If any interfaces have been added since the last public release, then
# increment age.
# If any interfaces have been removed since the last public release, then set
# age to 0.
set(SOVERSION "0.0.0")

string(TOLOWER ${CMAKE_SYSTEM_NAME} NAME_OS)
string(SUBSTRING ${NAME_OS} 0 3 NAME_OS)
# platform switches
if(CMAKE_SYSTEM_NAME MATCHES "^Linux$")
    set(LINUX 1)

elseif(CMAKE_SYSTEM_NAME MATCHES "^Darwin$")
    set(MAC 1)
    set(NAME_OS mac)

elseif(CMAKE_SYSTEM_NAME MATCHES "^Windows$")
    set(WIN 1)
    if(NAME_ARCH MATCHES "^mingw")
        set(MINGW 1)
    else()
        set(MINGW 0)
    endif()

else()
    message(FATAL_ERROR "Unknown platform")
endif()

# in case we INCLUDE stuff
include(resources/helpers.cmake)

# dependencies
list(APPEND CMAKE_PREFIX_PATH ${MBEDTLS_BASE}/cmake)
list(APPEND CMAKE_PREFIX_PATH ${RFUTIL_BASE}/lib/cmake)
find_package(MbedTLS REQUIRED)
find_package(regify-util REQUIRED)
if(WIN AND NOT MINGW)
    # visual studio
    set(YAJL_INCLUDE_DIRS ${YAJL_BASE}\\include)
    set(YAJL_LIBRARY_DIRS ${YAJL_BASE}\\lib)
    set(CURL_INCLUDE_DIRS ${CURL_BASE}\\include)
    set(CURL_LIBRARY_DIRS ${CURL_BASE}\\lib)
    set(CURL_LIBRARIES libcurl.lib zlib.lib ws2_32.lib crypt32.lib)

else()
    find_package(PkgConfig REQUIRED)
    find_package(CURL REQUIRED)
    find_package(Threads REQUIRED)

    # get yajl for JSON parsing
    pkg_check_modules(YAJL yajl)
    if (YAJL_FOUND)
        message(Found yajl)
    endif(YAJL_FOUND)
    
endif()

if (NOT YAJL_FOUND)
  set(YAJL_INCLUDE_DIRS ${YAJL_BASE}/include)
  set(YAJL_LIBRARY_DIRS ${YAJL_BASE}/lib)
  set(YAJL_LIBRARIES -lyajl)
endif()

# core files
add_subdirectory(lib)
configure_file(include/${NAME}.h include/${NAME}.h @ONLY)

if(INCLUDE_MBEDTLS AND DOCS)
    file(GLOB DEF_MBEDTLS_LICENSE_PATH ${MBEDTLS_BASE}/share/mbedtls/LICENSE)
    set(MBEDTLS_LICENSE_PATH ${DEF_MBEDTLS_LICENSE_PATH} CACHE STRING
            "Where the Mbed TLS License file for packaging can be found")
    if(MBEDTLS_LICENSE_PATH STREQUAL "")
        message(FATAL_ERROR "We need the Mbed TLS License file for packaging set MBEDTLS_LICENSE_PATH to its location")
    endif()
endif()

if(INCLUDE_YAJL AND DOCS)
    file(GLOB DEF_YAJL_LICENSE_PATH ${YAJL_BASE}/share/yajl/LICENSE)
    set(YAJL_LICENSE_PATH ${DEF_YAJL_LICENSE_PATH} CACHE STRING
            "Where the YAJL License file for packaging can be found")
    if(YAJL_LICENSE_PATH MATCHES "$^")
        message(FATAL_ERROR "We need the YAJL License file for packaging set YAJL_LICENSE_PATH to its location")
    endif()
endif()

# installation
include(CMakePackageConfigHelpers)
# generate the config file that is includes the exports
configure_package_config_file(${CMAKE_CURRENT_SOURCE_DIR}/resources/Config.cmake.in
        "${CMAKE_CURRENT_BINARY_DIR}/VaccinatorConfig.cmake"
        INSTALL_DESTINATION "lib/cmake/vaccinator"
        NO_SET_AND_CHECK_MACRO
        NO_CHECK_REQUIRED_COMPONENTS_MACRO )
write_basic_package_version_file(
        "${CMAKE_CURRENT_BINARY_DIR}/VaccinatorConfigVersion.cmake"
        VERSION "${DvLib_VERSION_MAJOR}.${DvLib_VERSION_MINOR}"
        COMPATIBILITY AnyNewerVersion
)
install(FILES
        ${CMAKE_CURRENT_BINARY_DIR}/VaccinatorConfig.cmake
        ${CMAKE_CURRENT_BINARY_DIR}/VaccinatorConfigVersion.cmake
        DESTINATION lib/cmake/vaccinator
        )
install(EXPORT VaccinatorTargets
        FILE VaccinatorTargets.cmake
        DESTINATION lib/cmake/vaccinator )
install(DIRECTORY include/
        DESTINATION include)

# tests
if(TESTING)
    message("Adding unit tests")
    enable_testing()
    add_subdirectory(tests)
else(TESTING)
    message("Skipping unit tests")
endif(TESTING)

# examples
if(SAMPLES)
    message("Adding examples")
    add_subdirectory(examples)
endif(SAMPLES)

# documetation
if(DOCS)
    # add a target to generate API documentation with Doxygen
    # add these to your PATH id they're not found even though they are installed
    find_package(Doxygen REQUIRED)

    # regify-utils linkage
    option(RULINK "Whether to link the regify-utils documentation" OFF)

    if(RULINK)
        set(RUBASE http://adocs.de.regify.com/docs/regify-util/1.2/api_doc
                CACHE STRING "Where the tag file for regify-utils can be found")

        find_program(CURL_EXECUTABLE
                NAMES curl curl.exe
                REQUIRED)
        set(RUTAG ${RUBASE}/regify-util.tag)
        set(RUTAG_FILE ${CMAKE_BINARY_DIR}/regify-util.tag)
        add_custom_target(rutag
                COMMAND ${CURL_EXECUTABLE} ${RUTAG} -o ${RUTAG_FILE}
                BYPRODUCTS ${RUTAG_FILE})
        # very manual for now
        set(DOC_TAGFILES "${RUTAG_FILE}=${RUBASE}")
    endif()

    set(DOC_INPUT "${CMAKE_BINARY_DIR}/include")

    configure_file(${CMAKE_SOURCE_DIR}/resources/Doxyfile.in
            ${CMAKE_BINARY_DIR}/Doxyfile @ONLY)
    add_custom_target(doc ALL
            COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_BINARY_DIR}/Doxyfile
            WORKING_DIRECTORY ${CMAKE_BINARY_DIR}
            COMMENT "Generating API documentation with Doxygen"
            VERBATIM
            )
    if(RULINK)
        add_dependencies(doc rutag)
    endif()
    install(DIRECTORY ${CMAKE_BINARY_DIR}/doc/html/
            DESTINATION share/${NAME}/doc)

    install(FILES LICENSE DESTINATION share/${NAME})
    if(INCLUDE_MBEDTLS)
        message("Bundling Mbed TLS License ${MBEDTLS_LICENSE_PATH}")
        install(FILES ${MBEDTLS_LICENSE_PATH}
                DESTINATION share/${NAME}
                RENAME MbedTLS-LICENSE)
    endif()
    if(INCLUDE_YAJL)
        message("Bundling YAJL License ${YAJL_LICENSE_PATH}")
        install(FILES ${YAJL_LICENSE_PATH}
                DESTINATION share/${NAME}
                RENAME YAJL-LICENSE)
    endif()

endif()

# packaging
include(InstallRequiredSystemLibraries)
set(CPACK_RESOURCE_FILE_LICENSE "${CMAKE_SOURCE_DIR}/LICENSE")
set(CPACK_PACKAGE_NAME ${PROJECT_NAME})
set(CPACK_PACKAGE_VERSION ${PROJECT_VERSION}-${REVISION})
set(CPACK_SYSTEM_NAME ${NAME_OS}.${NAME_ARCH})
set(CPACK_GENERATOR ZIP)
list(APPEND CPACK_SOURCE_IGNORE_FILES /cmake-.*/ /build.*/ /.git/ /.idea/)
set(CPACK_SOURCE_PACKAGE_FILE_NAME "${PROJECT_NAME}-${PROJECT_VERSION}-src")
set(CPACK_SOURCE_GENERATOR ZIP)
include(CPack)

# debugging
#dump("")
