cmake_dummy = """
cmake_minimum_required(VERSION 3.13 FATAL_ERROR)
project({})

set(SOURCE_LIST
    {}
)

add_library(${{PROJECT_NAME}} SHARED ${{SOURCE_LIST}})
"""