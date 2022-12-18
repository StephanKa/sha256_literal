# Generic test that uses conan libs
SET(PROJECT_NAME sha256_example)
ADD_EXECUTABLE(${PROJECT_NAME} main.cpp sha256.cpp)
TARGET_LINK_LIBRARIES(${PROJECT_NAME}
                      PRIVATE project_options
                      project_warnings
                      CONAN_PKG::fmt)

TARGET_INCLUDE_DIRECTORIES(${PROJECT_NAME} PRIVATE ../include)
