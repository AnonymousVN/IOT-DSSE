cmake_minimum_required(VERSION 3.16)
project (IOTSSE)

set(CMAKE_CXX_STANDARD 17)

FIND_PACKAGE(OpenSSL REQUIRED)

INCLUDE_DIRECTORIES(Core Util Util/PBC /usr/local/include)

# add link directory for PBC
LINK_DIRECTORIES(Util/PBC /usr/local/lib)

ADD_LIBRARY(PBC STATIC
        Util/PBC/G.cc
        Util/PBC/G1.cc
        Util/PBC/G2.cc
        Util/PBC/GT.cc
        Util/PBC/Pairing.cc
        Util/PBC/PPPairing.cc
        Util/PBC/Zr.cc)

TARGET_LINK_LIBRARIES(PBC -lgmp -lpbc)

add_executable(ChameleonHashTest Test/ChameleonHashTest.cpp Util/ChameleonHash.cpp)
add_executable(IOTSSE main.cpp Core/IOTSSEDBOwner.cpp Core/IOTSSEServer.cpp Core/IOTSSEUser.cpp Util/ChameleonHash.cpp Util/CommonUtils.cpp)

TARGET_LINK_LIBRARIES(ChameleonHashTest PBC)
TARGET_LINK_LIBRARIES(IOTSSE OpenSSL::SSL gmp PBC)

