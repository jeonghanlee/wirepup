TOP := $(CURDIR)
ifneq (1, $(words $(TOP)))
TOP := .
endif

MAKEFLAGS += --no-print-directory
.DEFAULT_GOAL := help

include $(TOP)/configure/CONFIG
include $(TOP)/configure/RULES
