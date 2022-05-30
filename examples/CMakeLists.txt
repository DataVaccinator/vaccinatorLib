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

set(PROVIDER_URL https://my.provider.com/dv CACHE STRING
        "The test service provider URL that connects to the vault")
set(APPID 1Ha6xo2u{mRT18 CACHE STRING "The test appid to use")
set(CACHE_DIR ${CMAKE_CURRENT_BINARY_DIR}/cache CACHE STRING
        "Where the local file cache resides")

if(WIN AND NOT MINGW)
    add_compile_definitions(_CRT_SECURE_NO_DEPRECATE CURL_STATICLIB=ON)
    add_compile_options(
            /MP /Wall /WX /wd4100 /wd4255 /wd4668 /wd4710 /wd4711 /wd4820 /wd5045
    )

else()
    add_compile_options(-Wall --pedantic)

endif()

add_compile_definitions (
        PROVIDER_URL=\"${PROVIDER_URL}\"
        APPID=\"${APPID}\"
        CACHE_DIR=\"${CACHE_DIR}\"
)

include_directories(${CMAKE_SOURCE_DIR}/include)
# staticlib sharedlib
function(dosample name)
    add_executable(${name} ${name}.c)
    add_dependencies(${name} ${staticlib})
    target_link_libraries(${name} ${staticlib})
    install(TARGETS ${name} DESTINATION bin)
endfunction()

dosample(changeappid)
dosample(publish)
dosample(datause)
