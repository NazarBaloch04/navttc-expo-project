cmake_minimum_required(VERSION 3.21)

project(RansomwareBehaviorMonitor LANGUAGES CXX)

add_executable(RansomwareBehaviorMonitor WIN32 ransomwhere.cpp)
target_compile_features(RansomwareBehaviorMonitor PRIVATE cxx_std_17)
target_link_libraries(RansomwareBehaviorMonitor PRIVATE
    Comctl32
    Shell32
    Ole32
    Comdlg32
)
