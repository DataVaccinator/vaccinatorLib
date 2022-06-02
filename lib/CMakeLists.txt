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

function (doLink lib shared)

    target_include_directories(${lib} PRIVATE ${CMAKE_SOURCE_DIR}/include)

    # regify-util
    if(shared)
        target_link_libraries(${lib} PUBLIC RegifyUtil::regify-util)
    else()
        target_link_libraries(${lib} PUBLIC RegifyUtil::regify-util_static)
    endif()

    # Mbed TLS
    if(shared AND INCLUDE_MBEDTLS)
        set(MBEDTLS_SCOPE PRIVATE)
    else()
        set(MBEDTLS_SCOPE PUBLIC)
    endif()
    if(shared AND NOT INCLUDE_MBEDTLS)
        target_link_libraries(${lib} ${MBEDTLS_SCOPE} MbedTLS::mbedcrypto)
    else()
        target_link_libraries(${lib} ${MBEDTLS_SCOPE} MbedTLS::mbedcrypto_static)
    endif()
    if(INSTALL_DEPS AND NOT shared AND INCLUDE_MBEDTLS)
        getlibs(MbedTLS::mbedcrypto_static "" "mbedcrypto")
    endif()

    # YAJL
    if(WIN AND NOT MINGW)
        if(shared)
            set(YAJL_LIBRARIES yajl.dll.lib)
        else()
            set(YAJL_LIBRARIES yajl.lib)
        endif()
    endif()
    if(shared AND INCLUDE_YAJL)
        set(YAJL_SCOPE PRIVATE)
    else()
        set(YAJL_SCOPE PUBLIC)
    endif()
    target_include_directories(${lib} ${YAJL_SCOPE} ${YAJL_INCLUDE_DIRS})
    if(YAJL_LIB)
        target_link_libraries(${lib} ${YAJL_SCOPE} ${YAJL_LIB})
        if(INSTALL_DEPS AND NOT shared AND INCLUDE_YAJL)
            getlibs("${YAJL_LIB}" "" "yajl")
        endif()
    else()
        target_link_directories(${lib} ${YAJL_SCOPE} ${YAJL_LIBRARY_DIRS})
        target_link_libraries(${lib} ${YAJL_SCOPE} ${YAJL_LIBRARIES})
        if(INSTALL_DEPS AND NOT shared AND INCLUDE_YAJL)
            getlibs("${YAJL_LIBRARIES}" "${YAJL_LIBRARY_DIRS}" "yajl")
        endif()
    endif()

    # cURL
    if(shared AND INCLUDE_CURL)
        set(CURL_SCOPE PRIVATE)
    else()
        set(CURL_SCOPE PUBLIC)
    endif()
    target_include_directories(${lib} ${CURL_SCOPE} ${CURL_INCLUDE_DIRS})
    if(CURL_LIB)
        target_link_libraries(${lib} ${CURL_SCOPE} ${CURL_LIB})
        if(INSTALL_DEPS AND NOT shared AND INCLUDE_CURL)
            getlibs("${CURL_LIB}" "" "curl")
        endif()
    else()
        target_link_directories(${lib} ${CURL_SCOPE} ${CURL_LIBRARY_DIRS})
        target_link_libraries(${lib} ${CURL_SCOPE} ${CURL_LIBRARIES})
        if(INSTALL_DEPS AND NOT shared AND INCLUDE_CURL)
            getlibs("${CURL_LIBRARIES}" "${CURL_LIBRARY_DIRS}" "curl")
        endif()
    endif()

    if(WIN AND NOT MINGW)
        target_compile_definitions(${lib}
                PRIVATE _CRT_SECURE_NO_DEPRECATE CURL_STATICLIB)
        target_compile_options(${lib}
                PRIVATE /MP /Wall /WX /wd4100 /wd4204 /wd4255 /wd4431 /wd4668
                /wd4710 /wd4711 /wd4774 /wd4820 /wd5045
        )
        if(shared)
            set_target_properties(${lib} PROPERTIES VERSION ${PROJECT_VERSION})
        endif()

    else()
        target_compile_options(${lib}
                PRIVATE -Wall -Werror --pedantic
                ${CMAKE_C_COMPILE_OPTIONS_PIC}
                -ffunction-sections -fdata-sections -fvisibility=hidden
        )
        if(shared)
            set_target_properties(${lib} PROPERTIES SOVERSION ${SOVERSION})
        endif()

    endif()
    if(INSTALL_DEPS AND NOT shared)
        set(EXTRA_ARCHIVES ${EXTRA_ARCHIVES} PARENT_SCOPE)
    endif()
endfunction()

if(INSTALL_DEPS)
    set(EXTRA_ARCHIVES "")
endif()

set(SOURCES lib.c json.c misc.c curl.c crypto.c)

add_library(${staticlib} STATIC ${SOURCES})
doLink(${staticlib} OFF)
if(NOT WIN OR MINGW)
    set_target_properties(${staticlib} PROPERTIES OUTPUT_NAME ${NAME})
endif()
install(TARGETS ${staticlib}
        EXPORT VaccinatorTargets
        DESTINATION lib)

if(BUILD_SHARED_LIBS)
    add_library(${sharedlib} SHARED ${SOURCES})
    doLink(${sharedlib} ON)
    install(TARGETS ${sharedlib}
            EXPORT VaccinatorTargets
            DESTINATION lib)
endif()

if(INSTALL_DEPS)
    foreach(lib ${EXTRA_ARCHIVES})
        install(FILES ${lib} DESTINATION lib)
        message("installing ${lib}")
    endforeach()
endif()
