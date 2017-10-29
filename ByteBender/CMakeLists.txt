cmake_minimum_required(VERSION 3.8)
project(ByteBender)

set(CMAKE_CXX_FLAGS "${CMAKE_CXX_FLAGS} -std=c++17")

link_directories(/usr/local/lib/ /usr/lib/x86_64-linux-gnu/)

include_directories(/usr/local/include/bsoncxx/v_noabi/ /usr/local/include/mongocxx/v_noabi/ /usr/local/include/libpcap-1.8.1)

set(SOURCE_FILES main.cpp ContentHandler.cpp ContentHandler.h)
add_executable(ByteBender ${SOURCE_FILES})

find_package(Threads)
find_package(libbsoncxx)
find_package(libmongocxx)
target_link_libraries(ByteBender ${CMAKE_THREAD_LIBS_INIT} proxygenhttpserver folly glog GeoIP ${LIBMONGOCXX_LIBRARIES} ${LIBBSONCXX_LIBRARIES} pcap)
