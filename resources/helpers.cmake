
function (getlibs libs dirs inclusions)
    # extracts paths to static libraries from given paths or imports
    foreach(lib IN LISTS libs)
        if(lib MATCHES "::")
            get_target_property(x ${lib} IMPORTED_LOCATION)
            if(NOT x STREQUAL "x-NOTFOUND")
                message("${lib} got: ${x}")
                list(APPEND EXTRA_ARCHIVES ${x})
                continue()
            endif()
            get_target_property(x ${lib} IMPORTED_LOCATION_RELEASE)
            if(NOT x STREQUAL "x-NOTFOUND")
                message("${lib} got: ${x}")
                list(APPEND EXTRA_ARCHIVES ${x})
                continue()
            endif()
            get_target_property(x ${lib} IMPORTED_LOCATION_DEBUG)
            if(NOT x STREQUAL "x-NOTFOUND")
                message("${lib} got: ${x}")
                list(APPEND EXTRA_ARCHIVES ${x})
            endif()
            continue()
        endif()

        if(NOT lib MATCHES ${inclusions})
            message("Excluding ${lib}")
            continue()
        endif()

        if(EXISTS ${lib})
            set(mylib ${lib})
            message("got ${mylib}")
            list(APPEND EXTRA_ARCHIVES ${mylib})
            continue()
        endif()

        if(lib MATCHES "^-l")
            string(SUBSTRING ${lib} 2 -1 base)
        else()
            set(base ${lib})
        endif()
        message("base ${base}")
        if(base MATCHES "${CMAKE_STATIC_LIBRARY_SUFFIX}$")
            set(arch ${base})
        else()
            set(arch ${CMAKE_STATIC_LIBRARY_PREFIX}${base}${CMAKE_STATIC_LIBRARY_SUFFIX})
        endif()
        message("arch ${arch}")
        find_file(x ${arch} PATHS ${dirs} NO_DEFAULT_PATH)
        if(NOT x STREQUAL "x-NOTFOUND")
            message("got ${x}")
            list(APPEND EXTRA_ARCHIVES ${x})
        endif()

    endforeach()
    set (EXTRA_ARCHIVES ${EXTRA_ARCHIVES} PARENT_SCOPE)
endfunction()

function(dump match)
    if(match STREQUAL "")
        set(all 1)
        message("VARIABLES:")
    else()
        set(all 0)
        message("VARIABLES matching: ${match}")
    endif()

    get_cmake_property(_variableNames VARIABLES)
    list (SORT _variableNames)
    foreach (_variableName ${_variableNames})
        if(all OR "${_variableName}" MATCHES "${match}")
            string(SUBSTRING "${${_variableName}}" 0 200 VAL)
            string(REGEX REPLACE \n "\\\\n" VAL "${VAL}")
            message("${_variableName}: ${VAL}")
        endif()
    endforeach()
endfunction()