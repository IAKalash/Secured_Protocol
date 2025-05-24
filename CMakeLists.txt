cmake_minimum_required(VERSION 3.10)
project(SecuredProtocol C)

set(CMAKE_C_STANDARD 11)
set(CMAKE_C_STANDARD_REQUIRED ON)

set(SOURCE_DIR "${CMAKE_SOURCE_DIR}/src")
set(INCLUDE_DIR "${CMAKE_SOURCE_DIR}/include")
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY "${CMAKE_BINARY_DIR}/bin")

file(GLOB SOURCES "${SOURCE_DIR}/*.c")
include_directories(${INCLUDE_DIR})

add_executable(${PROJECT_NAME} ${SOURCES})

set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} -Wno-deprecated-declarations")

function(check_and_install_package package_name install_command)
    find_program(${package_name}_FOUND ${package_name})
    if(NOT ${package_name}_FOUND)
        message(STATUS "${package_name} not found. Attempting to install on Linux...")
        execute_process(
            COMMAND bash -c "${install_command}"
            RESULT_VARIABLE INSTALL_RESULT
        )
        if(NOT INSTALL_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to install ${package_name}. Please install it manually using: ${install_command}")
        endif()
        find_program(${package_name}_FOUND ${package_name})
        if(NOT ${package_name}_FOUND)
            message(FATAL_ERROR "${package_name} still not found after installation attempt. Please install it manually.")
        endif()
    else()
        message(STATUS "${package_name} found.")
    endif()
endfunction()

if(UNIX AND NOT APPLE) 
    message(STATUS "Detected Linux system. Checking dependencies...")

    check_and_install_package("gcc" "sudo apt update && sudo apt install -y build-essential")

    check_and_install_package("cmake" "sudo apt update && sudo apt install -y cmake")

    find_package(OpenSSL QUIET)
    if(NOT OpenSSL_FOUND)
        message(STATUS "OpenSSL not found. Attempting to install libssl-dev...")
        execute_process(
            COMMAND bash -c "sudo apt update && sudo apt install -y libssl-dev"
            RESULT_VARIABLE INSTALL_OPENSSL_RESULT
        )
        if(NOT INSTALL_OPENSSL_RESULT EQUAL 0)
            message(FATAL_ERROR "Failed to install libssl-dev. Please install it manually using: sudo apt update && sudo apt install -y libssl-dev")
        endif()
        find_package(OpenSSL REQUIRED)
        if(NOT OpenSSL_FOUND)
            message(FATAL_ERROR "OpenSSL still not found after installation attempt. Please install it manually.")
        endif()
    endif()

    set(CMAKE_GENERATOR "Unix Makefiles" CACHE STRING "Generator for Linux" FORCE)

elseif(WIN32)
    set(OPENSSL_ROOT_DIR "C:/msys64/mingw64" CACHE PATH "Path to OpenSSL root directory")
    set(OPENSSL_INCLUDE_DIR "C:/msys64/mingw64/include" CACHE PATH "Path to OpenSSL include directory")
    set(OPENSSL_LIBRARY_DIR "C:/msys64/mingw64/lib" CACHE PATH "Path to OpenSSL library directory")
    set(CMAKE_GENERATOR "MinGW Makefiles" CACHE STRING "Generator for Windows" FORCE)
    set(CMAKE_C_COMPILER "C:/msys64/mingw64/bin/gcc.exe" CACHE FILEPATH "C Compiler" FORCE)

    find_package(OpenSSL REQUIRED)
    if(NOT OpenSSL_FOUND)
        message(FATAL_ERROR "OpenSSL not found. Please install it via MSYS2:\n"
                            "  1. Install MSYS2 from https://www.msys2.org/\n"
                            "  2. Run: pacman -Syu\n"
                            "  3. Run: pacman -S mingw-w64-x86_64-gcc mingw-w64-x86_64-cmake mingw-w64-x86_64-openssl")
    endif()

else()
    message(FATAL_ERROR "Unsupported platform. This project supports Linux and Windows only.")
endif()

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