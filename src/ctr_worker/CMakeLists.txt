add_executable(ctr-worker main.cpp)
target_link_libraries(ctr-worker PRIVATE citra_core json-headers)
execute_process(COMMAND git rev-parse HEAD WORKING_DIRECTORY "${PROJECT_SOURCE_DIR}"
    OUTPUT_VARIABLE CTR_SOURCE_SHA OUTPUT_STRIP_TRAILING_WHITESPACE COMMAND_ERROR_IS_FATAL ANY)
target_compile_definitions(ctr-worker PRIVATE CTR_SOURCE_SHA="${CTR_SOURCE_SHA}")
if (WIN32)
    target_link_libraries(ctr-worker PRIVATE crypt32)
endif()
