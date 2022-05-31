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
set(CHECK_BASE ${DEPS_BASE} CACHE STRING "libcheck installation prefix")
set(PROVIDER_URL https://my.provider.com/dv CACHE STRING
        "The test service provider URL that connects to the vault")
set(VAULT_ID 1 CACHE STRING
        "The test data vaccinator vault ID to authenticate with")
set(VAULT_PW vaccinator CACHE STRING
        "The test data vaccinator vault password to authenticate with")

list(APPEND CMAKE_PREFIX_PATH ${CHECK_BASE})
list(APPEND CMAKE_MODULE_PATH "${CMAKE_SOURCE_DIR}/tests/")
find_package(Check REQUIRED)

if(WIN AND NOT MINGW)
    add_compile_definitions(_CRT_SECURE_NO_DEPRECATE CURL_STATICLIB=ON)
    add_compile_options( /MP /Wall /WX
            /wd4100 /wd4255 /wd4464 /wd4668 /wd4710 /wd4820 /wd5045
    )

else()
    add_compile_options(-Wall -Werror --pedantic)

endif()

add_compile_definitions (
        PROVIDER_URL=\"${PROVIDER_URL}\"
        VAULT_ID=\"${VAULT_ID}\"
        VAULT_PW=\"${VAULT_PW}\"
        CACHE_DIR=\"${CMAKE_CURRENT_BINARY_DIR}/cache\"
)
include_directories( ${CMAKE_SOURCE_DIR}/include )

add_executable(tests test.c cipher.c vacc.c caching.c change.c)
# we use staticlib instead of sharedlib because we test internal functions
# and -fvisibility=hidden hides these from us
add_dependencies(tests ${staticlib})
target_link_libraries(tests ${staticlib} ${CHECK_LIBRARIES} )

message("CMAKE_PREFIX_PATH = ${CMAKE_PREFIX_PATH}")