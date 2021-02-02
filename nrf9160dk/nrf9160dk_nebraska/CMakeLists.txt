#
# Copyright (c) 2021 IoTerop
# (based on Nordic Semiconductor Sample Code)
#
#

cmake_minimum_required(VERSION 3.13.1)

find_package(Zephyr REQUIRED HINTS $ENV{ZEPHYR_BASE})
project(nrf9160dk-nebraska-client)

# NORDIC SDK APP START
target_sources(app PRIVATE src/main.c)
# NORDIC SDK APP END
