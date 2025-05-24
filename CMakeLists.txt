cmake_minimum_required(VERSION 3.10)
project(SecuredProtocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

file(GLOB_RECURSE SOURCES "${SOURCE_DIR}/*.c")
include_directories(${INCLUDE_DIR})

add_executable(${PROJECT_NAME} ${SOURCES})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")

set(OPENSSL_ROOT_DIR "C:/msys64/mingw64" CACHE PATH "Path to OpenSSL root directory")
set(OPENSSL_INCLUDE_DIR "C:/msys64/mingw64/include" CACHE PATH "Path to OpenSSL include directory")
set(OPENSSL_LIBRARY_DIR "C:/msys64/mingw64/lib" CACHE PATH "Path to OpenSSL library directory")

find_package(OpenSSL REQUIRED)
if(OpenSSL_FOUND)
    message(STATUS "OpenSSL found: ${OPENSSL_VERSION}")
    message(STATUS "OpenSSL include dir: ${OPENSSL_INCLUDE_DIR}")
    message(STATUS "OpenSSL libraries: ${OPENSSL_LIBRARIES}")
    target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE ${OPENSSL_LIBRARIES})
else()
    message(FATAL_ERROR "OpenSSL not found. Please ensure it is installed and try again.")
endif()

if(WIN32)
    target_link_libraries(${PROJECT_NAME} PRIVATE ws2_32 crypt32)
endif()