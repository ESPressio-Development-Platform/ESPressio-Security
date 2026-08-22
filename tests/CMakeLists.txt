cmake_minimum_required(VERSION 3.16)
project(ESPressioSecurityTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

include(FetchContent)
FetchContent_Declare(
    ESPressioObservable
    GIT_REPOSITORY https://github.com/ESPressio-Development-Platform/ESPressio-Observable.git
    GIT_TAG 3.0.1
    GIT_SHALLOW TRUE
)
FetchContent_GetProperties(ESPressioObservable)
if(NOT espressioobservable_POPULATED)
    FetchContent_Populate(ESPressioObservable)
endif()
set(ESPRESSIO_OBSERVABLE_INCLUDE ${espressioobservable_SOURCE_DIR}/src)

add_executable(Security test_security.cpp)
target_include_directories(Security PRIVATE ../src ${ESPRESSIO_OBSERVABLE_INCLUDE})
add_executable(SecureTransportDecorator test_decorator.cpp)
target_include_directories(SecureTransportDecorator PRIVATE ../src ${ESPRESSIO_OBSERVABLE_INCLUDE})
add_executable(MbedTLSCompile test_mbedtls_compile.cpp)
target_include_directories(MbedTLSCompile PRIVATE stubs ../src ${ESPRESSIO_OBSERVABLE_INCLUDE})
add_executable(SecurityObservable test_observable.cpp)
target_include_directories(SecurityObservable PRIVATE ../src ${ESPRESSIO_OBSERVABLE_INCLUDE})

enable_testing()
add_test(NAME Security COMMAND Security)
add_test(NAME SecureTransportDecorator COMMAND SecureTransportDecorator)
add_test(NAME MbedTLSCompile COMMAND MbedTLSCompile)
add_test(NAME SecurityObservable COMMAND SecurityObservable)
