CMAKE_MINIMUM_REQUIRED(VERSION 3.6 FATAL_ERROR)

foreach(policy CMP0068)
  if(POLICY ${policy})
    cmake_policy(SET ${policy} NEW)
  endif()
endforeach()

PROJECT(Crypt1CLib CXX)

IF(WIN32)
    ENABLE_LANGUAGE(RC)
ENDIF()

SET(Crypt1CLib_SRC
        dllmain.cpp
        AddInNative.cpp
        AddInNative.h
        crypt.cpp
        crypt.h)
if (WIN32)
    LIST(APPEND Crypt1CLib_SRC Crypt1CLib.rc crypt1clib.def)
endif()

SET(ADN_NAME ${PROJECT_NAME})
SET(MECONPANY "SapphireDev")

include_directories(${CMAKE_SOURCE_DIR}/include)

SET (CMAKE_PREFIX_PATH ${CMAKE_PREFIX_PATH} ${CMAKE_SOURCE_DIR})

if (WIN32)
    add_definitions(-DUNICODE -DWIN32 -D_USRDLL -D_CRT_SECURE_NO_WARNINGS -D_CRT_SECURE_NO_DEPRECATE -DADDINCPP_EXPORTS)
endif()

if (UNIX)
    link_libraries("-lcrypto -lssl")
endif()

add_library(Crypt1CLib SHARED ${Crypt1CLib_SRC})
target_include_directories(${PROJECT_NAME} PRIVATE ${CMAKE_CURRENT_BINARY_DIR})

if (WIN32)
    # Укажите путь к каталогу include библиотеки openssl.
    SET(OPENSSL_INCLUDE_DIR "d:/Visual Studio/libs/openssl/static/x64/release/include" CACHE PATH "Path to OpenSSL headers")
    # Укажите путь к каталогу библиотеки openssl.
    SET(OPENSSL_LIB_DIR "d:/Visual Studio/libs/openssl/static/x64/release/lib" CACHE PATH "Path to OpenSSL lib")
    
    target_include_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_INCLUDE_DIR})
    target_link_directories(${PROJECT_NAME} PRIVATE ${OPENSSL_LIB_DIR})
    target_link_libraries(${PROJECT_NAME} PRIVATE libssl.lib libcrypto.lib Crypt32.lib Ws2_32.lib)
endif()

set_target_properties( ${PROJECT_NAME} PROPERTIES
       POSITION_INDEPENDENT_CODE ON 
       CXX_STANDARD 11
       CXX_STANDARD_REQUIRED ON
   )
IF (UNIX AND NOT APPLE)
    set_target_properties(${PROJECT_NAME} PROPERTIES LINK_FLAGS "-Wl,--no-undefined -Xlinker --version-script -Xlinker ${CMAKE_CURRENT_SOURCE_DIR}/version.script" )
ENDIF()
