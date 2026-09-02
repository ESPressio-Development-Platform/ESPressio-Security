cmake_minimum_required(VERSION 3.16)
project(ESPressioSecurityTests LANGUAGES CXX)
set(CMAKE_CXX_STANDARD 17)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS ON)

include(FetchContent)
FetchContent_Declare(
    ESPressioSystem
    GIT_REPOSITORY https://github.com/ESPressio-Development-Platform/ESPressio-System.git
    GIT_TAG feature/1-system-memory-policy
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(ESPressioSystem)
set(ESPRESSIO_SYSTEM_INCLUDE ${espressiosystem_SOURCE_DIR}/src)

FetchContent_Declare(
    ESPressioObservable
    GIT_REPOSITORY https://github.com/ESPressio-Development-Platform/ESPressio-Observable.git
    GIT_TAG feature/16-rtti-free-observer-registry
    GIT_SHALLOW TRUE
)
FetchContent_MakeAvailable(ESPressioObservable)
set(ESPRESSIO_OBSERVABLE_INCLUDE ${espressioobservable_SOURCE_DIR}/src)

set(SECURITY_INCLUDES ../src ${ESPRESSIO_SYSTEM_INCLUDE} ${ESPRESSIO_OBSERVABLE_INCLUDE})

add_executable(Security test_security.cpp)
target_include_directories(Security PRIVATE ${SECURITY_INCLUDES})
add_executable(DataProtector test_data_protector.cpp)
target_include_directories(DataProtector PRIVATE ${SECURITY_INCLUDES})
add_executable(SecureTransportDecorator test_decorator.cpp)
target_include_directories(SecureTransportDecorator PRIVATE ${SECURITY_INCLUDES})
add_executable(MbedTLSCompile test_mbedtls_compile.cpp)
target_include_directories(MbedTLSCompile PRIVATE stubs ${SECURITY_INCLUDES})
add_executable(SecurityObservable test_observable.cpp)
target_include_directories(SecurityObservable PRIVATE ${SECURITY_INCLUDES})
add_executable(KeyProviderLifetime test_key_provider_lifetime.cpp)
target_include_directories(KeyProviderLifetime PRIVATE ${SECURITY_INCLUDES})

enable_testing()
add_test(NAME Security COMMAND Security)
add_test(NAME DataProtector COMMAND DataProtector)
add_test(NAME SecureTransportDecorator COMMAND SecureTransportDecorator)
add_test(NAME MbedTLSCompile COMMAND MbedTLSCompile)
add_test(NAME SecurityObservable COMMAND SecurityObservable)
add_test(NAME KeyProviderLifetime COMMAND KeyProviderLifetime)
