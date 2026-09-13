#===============================================================================
# @brief    cmake file
# Copyright (c) @CompanyNameMagicTag 2022-2022. All rights reserved.
#===============================================================================
add_subdirectory_if_exist(ws53_app_linker)
add_subdirectory_if_exist(ws53_ctrl_linker)
add_subdirectory_if_exist(romboot_linker)
add_subdirectory_if_exist(loaderboot_linker)
add_subdirectory_if_exist(flashboot_linker)
add_subdirectory_if_exist(acore_ate_linker)
add_subdirectory_if_exist(ccore_ate_linker)
add_subdirectory_if_exist(acore_flash_againg_test_linker)
add_subdirectory_if_exist(ws53_app_sw21_linker)
add_subdirectory_if_exist(ssb_linker)
