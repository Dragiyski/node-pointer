cmake_minimum_required(VERSION 3.16)
project(pointer)

include(CheckIncludeFiles)
include(CheckSymbolExists)
include(CheckLibraryExists)

# For Unix-like OS, we should have:
# - mmap() and mlock() (and munmap() and munlock() respectively) to allocate space for particular image at particular address;
# - mincore() to check if pointer is still valid without SIGSEGV
# - dlopen(), dlclose() and dlsym() to access symbols of an image.
check_include_files(unistd.h HAVE_UNISTD_H)
check_include_files(sys/mman.h HAVE_SYS_MMAN_H)
check_symbol_exists(mmap "sys/mman.h" HAVE_MMAP)
check_symbol_exists(munmap "sys/mman.h" HAVE_MUNMAP)
check_symbol_exists(mlock "sys/mman.h" HAVE_MLOCK)
check_symbol_exists(munlock "sys/mman.h" HAVE_MUNLOCK)
check_symbol_exists(mincore "sys/mman.h" HAVE_MINCORE)
check_symbol_exists(sysconf "unistd.h" HAVE_SYSCONF)
check_symbol_exists(_SC_PAGESIZE "unistd.h" HAVE_SYSCONF_SC_PAGESIZE)
check_include_files(dlfcn.h HAVE_DLFCN_H)
check_library_exists(dl dlopen "" HAVE_DLOPEN)
check_library_exists(dl dlclose "" HAVE_DLCLOSE)
check_library_exists(dl dlsym "" HAVE_DLSYM)
check_library_exists(dl dlinfo "" HAVE_DLINFO)

# For Windows platform, we should have:
# VirtualAlloc(), VirtualLock() (and VirtualFree() and VirtualUnlock() respectively) to allocate space for particular image at particular address;
# VirtualQuery() to check if pointer is still valid without access violation
check_include_files(Memoryapi.h HAVE_MEMORYAPI_H)
check_include_files(Libloaderapi.h HAVE_LIBLOADERAPI_H)
check_include_files(Windows.h HAVE_WINDOWS_H)
check_symbol_exists(VirtualAlloc "Memoryapi.h" HAVE_VIRTUAL_ALLOC)
check_symbol_exists(VirtualFree "Memoryapi.h" HAVE_VIRTUAL_FREE)
check_symbol_exists(VirtualLock "Memoryapi.h" HAVE_VIRTUAL_LOCK)
check_symbol_exists(VirtualUnlock "Memoryapi.h" HAVE_VIRTUAL_UNLOCK)
check_symbol_exists(VirtualQuery "Memoryapi.h" HAVE_VIRTUAL_QUERY)
check_symbol_exists(LoadLibraryW "Lobloaderapi.h" HAVE_LOAD_LIBRARY)
check_symbol_exists(FreeLibrary "Lobloaderapi.h" HAVE_FREE_LIBRARY)
check_symbol_exists(GetProcAddress "Lobloaderapi.h" HAVE_GET_RPOC_ADDRESS)
configure_file(${CMAKE_CURRENT_SOURCE_DIR}/config.h.in ${CMAKE_CURRENT_BINARY_DIR}/config.h)

file(GLOB SOURCE_FILES "./src/*.cpp")
add_library(${PROJECT_NAME} MODULE ${SOURCE_FILES} ${CMAKE_JS_SRC})
set_target_properties(${PROJECT_NAME} PROPERTIES PREFIX "" SUFFIX ".node")
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD 20)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_STANDARD_REQUIRED ON)
set_property(TARGET ${PROJECT_NAME} PROPERTY CXX_EXTENSIONS OFF)

target_include_directories(${PROJECT_NAME} SYSTEM PUBLIC ${CMAKE_JS_INC} ${CMAKE_CURRENT_BINARY_DIR})
target_link_libraries(${PROJECT_NAME} PUBLIC${CMAKE_JS_LIB})