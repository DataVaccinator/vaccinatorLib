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

set(SOURCES lib.c json.c misc.c curl.c crypto.c)

function (doLink lib shared)

    if(WIN AND NOT MINGW)
        # visual studio
        if(shared)
            set(RFUTIL_LIBRARIES regify-util.dll.lib)
            set(YAJL_LIBRARIES yajl.dll.lib)
            target_compile_definitions(${lib}
                    PRIVATE -DDV_SHARED
                    )

        else()
            set(RFUTIL_LIBRARIES regify-util.lib icuio.lib icuin.lib icuuc.lib icudt.lib)
            set(YAJL_LIBRARIES yajl.lib)
        endif()
    endif()

    target_include_directories(${lib}
            PUBLIC ${RFUTIL_INCLUDE_DIRS} ${YAJL_INCLUDE_DIRS}
            PRIVATE ${CMAKE_SOURCE_DIR}/include
            )
    target_link_directories(${lib}
            PUBLIC ${RFUTIL_LIBRARY_DIRS} ${YAJL_LIBRARY_DIRS}
            )
    target_link_libraries(${lib}
            PUBLIC ${RFUTIL_LIBRARIES} ${YAJL_LIBRARIES}
            )

    if(WIN AND NOT MINGW)
        target_compile_definitions(${lib}
                PRIVATE _CRT_SECURE_NO_DEPRECATE CURL_STATICLIB=ON
        )
        target_compile_options(${lib}
                PRIVATE /MP /Wall /WX /wd4100 /wd4204 /wd4255 /wd4431 /wd4668
                /wd4710 /wd4711 /wd4774 /wd4820 /wd5045
        )
        target_include_directories(${lib}
                PRIVATE ${CURL_INCLUDE_DIRS}
                )
        target_link_directories(${lib}
                PRIVATE ${CURL_LIBRARY_DIRS}
                )
        target_link_libraries(${lib}
                PRIVATE MbedTLS::mbedcrypto ${CURL_LIBRARIES}
                )
        if(shared)
            set_target_properties(${lib} PROPERTIES VERSION ${PROJECT_VERSION})
        endif()

    else()
        target_compile_options(${lib}
                PRIVATE -Wall -Werror --pedantic
                -fPIC -ffunction-sections -fdata-sections
        )
        if (CMAKE_BUILD_TYPE MATCHES "Release")
            # this is so that tests can access internal function to test
            # FIXME not optimal and not windows either
            target_compile_options(${lib}
                    PRIVATE -fvisibility=hidden
                    )
        endif()
        target_include_directories(${lib}
                PUBLIC ${CURL_INCLUDE_DIRS}
                )
        target_link_directories(${lib}
                PUBLIC ${CURL_LIBRARY_DIRS}
                )
        target_link_libraries(${lib}
                PUBLIC MbedTLS::mbedcrypto ${CURL_LIBRARIES}
                )
        if(shared)
            set_target_properties(${lib} PROPERTIES SOVERSION ${SOVERSION})
        endif()

    endif()
endfunction()

if(BUILD_SHARED_LIBS)
    add_library(${sharedlib} SHARED ${SOURCES})
    doLink(${sharedlib} ON)
    install(TARGETS ${sharedlib}
            EXPORT VaccinatorTargets
            DESTINATION lib)
endif()

add_library(${staticlib} STATIC ${SOURCES})
doLink(${staticlib} OFF)
if(NOT WIN OR MINGW)
    set_target_properties(${staticlib} PROPERTIES OUTPUT_NAME ${NAME})
endif()
install(TARGETS ${staticlib}
        EXPORT VaccinatorTargets
        DESTINATION lib)


