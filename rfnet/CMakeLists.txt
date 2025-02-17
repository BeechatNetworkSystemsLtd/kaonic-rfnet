
add_library(modules_rfnet)

target_sources(
    modules_rfnet

        PRIVATE
            src/rfnet.c
)

target_include_directories(
    modules_rfnet

        PUBLIC
        ${CMAKE_CURRENT_SOURCE_DIR}/include/
)

