# refer to : https://greenfishblog.tistory.com/254

###############################################################
# Makefile by finl team
###############################################################

###############################################################
# basic make command
###############################################################

# make                           : debug build   (native)
# make debug                     : debug build   (native)
# make release                   : release build (native)
# make rebuild [debug, release]  : rebuild       (native)
# make clean [debug, release]    : clean

###############################################################
# detect OS
###############################################################
ifeq ($(OS),Windows_NT)     # is Windows_NT on XP, 2000, 7, Vista, 10...
    # detected_OS := Windows
	PLATFORM   = win
else
    # detected_OS := $(shell uname)  # same as "uname -s"
	PLATFORM   = linux
endif

###############################################################
# get makefile command line argument
###############################################################

ifneq "$(findstring clean, $(MAKECMDGOALS))" ""
    ARG.CLEAN = 1
endif
ifneq "$(findstring release, $(MAKECMDGOALS))" ""
    ARG.RELEASE = 1
endif
ifneq "$(findstring debug, $(MAKECMDGOALS))" ""
    ARG.DEBUG = 1
endif
ifneq "$(findstring rebuild, $(MAKECMDGOALS))" ""
    ARG.REBUILD = 1
endif

###############################################################
# DEBUG / RELEASE build option branch
###############################################################
# EXTRA_CFLAGS += -Wall -Werror -fstack-protector-all -std=c++11
EXTRA_CFLAGS += -Wall -Werror -std=c++11

ifeq ($(ARG.RELEASE),1)
    # -----------------
    # for release build
    # -----------------
    EXTRA_CFLAGS    += -DNDEBUG -O2
    CONFIG    = release
else
    # ---------------
    # for debug build
    # ---------------
    # EXTRA_CFLAGS    += -g -rdynamic -DDEBUG -O0
	EXTRA_CFLAGS    += -g -export-dynamic -DDEBUG -O0

#     EXTRA_CFLAGS    += -g -DDEBUG -O0
# ifeq ($(PLATFORM),$(filter $(PLATFORM), win))
#     EXTRA_CFLAGS    += -export-dynamic
# else
#     EXTRA_CFLAGS    += -rdynamic
# endif #

    CONFIG    = debug
endif

###############################################################
# set default compile options
###############################################################
MAKE_SO = no
MAKE_A = no

CC = gcc
CXX = g++
STRIP      = strip
# PLATFORM   = linux
# CONFIG     = debug
ifeq ($(MAKE_SO),$(filter $(MAKE_SO), yes))
    LIBNAME    = libcryptof.so
    LIBCOMPILE = -fPIC
    LIBLINK    = -shared -Wl,-soname,$(LIBNAME),--version-script=ld_conf.lds
else ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
    LIBNAME    = libcryptof.a
    LIBCOMPILE =
    LIBLINK    =
else
    LIBNAME    = cryptof
    LIBCOMPILE =
    LIBLINK    =
endif #
#
#TRUNK_DIR  = $(abspath ../..)
TRUNK_DIR  = ../../..
#
SRC_DIR    = $(TRUNK_DIR)/src
#
BUILD_DIR  = $(TRUNK_DIR)/app/lua/build/$(PLATFORM)/$(CONFIG)
#
TARGET     = $(BUILD_DIR)/$(LIBNAME)
TARGET_LIB = $(LIB_CFG_DIR)/$(LIBNAME)
#
# OBJ_DIR    = $(TRUNK_DIR)/obj
OBJ_DIR    = $(BUILD_DIR)/obj
OBJ_CFG_DIR= $(OBJ_DIR)/$(CONFIG)
#
LIB_DIR    = $(TRUNK_DIR)/lib
LIB_CFG_DIR= $(LIB_DIR)/$(CONFIG)
INC_DIR    = 
PRE_DEFS   =
SYSROOT    =

###############################################################
# include config files
###############################################################
include ./../conf/lua.cfg

#
VER_INFO_STR = $(VER_INFO)

#
ifeq ($(PLATFORM),$(filter $(PLATFORM), win))
    LIB_DEF_PATH_STR = $(LIB_PATH_WIN)
else
    LIB_DEF_PATH_STR = $(LIB_PATH)
endif #

ifeq ($(PLATFORM),$(filter $(PLATFORM), win))
    INC_DEF_PATH_STR = $(INC_PATH_WIN)
else
    INC_DEF_PATH_STR = $(INC_PATH)
endif #

#
CFG_PATH_STR = $(CFG_PATH)

#
# LOG_PATH_STR = $(LOG_PATH)
# LOG_NAME_STR = $(LOG_NAME)

#
# DEV_ID_STR = $(DEV_ID)

#
PRE_DEFS += -DVER_INFO=\"$(VER_INFO_STR)\"

#
PRE_DEFS += -DCFG_PATH=\"$(CFG_PATH_STR)\"

#
# PRE_DEFS += -DDATA_LOG_PATH=\"$(LOG_PATH_STR)\"
# PRE_DEFS += -DDATA_LOG_FILE_PATH=\"$(LOG_PATH_STR)/$(LOG_NAME_STR)\"

#
# PRE_DEFS += -DDEV_ID=\"$(DEV_ID_STR)\"

EXTRA_CFLAGS += $(PRE_DEFS)

###############################################################
# Libraries & Include
# LDFLAGS += -pthread -lrt -lm -ldl
LDFLAGS += -pthread -lm

#
ifeq ($(PLATFORM),$(filter $(PLATFORM), win))
    LDFLAGS += -L$(LIB_DEF_PATH_STR)/libcrypto/openssl_111a
    LDFLAGS += -L$(LIB_DEF_PATH_STR)/liblua/lua5.2
	LDFLAGS += -L$(LIB_DEF_PATH_STR)/libcurl/curl7.79.1
	LDFLAGS += -L$(LIB_DEF_PATH_STR)/libutf8
    
    LDFLAGS += -llua52 
    LDFLAGS += -lcrypto-1_1-x64
    LDFLAGS += -lssl-1_1-x64

	LDFLAGS += -lcurl-x64
	LDFLAGS += -lutf8proc
	
    # LDFLAGS += -lssl
    # LDFLAGS += -lcrypto 
	# LDFLAGS += -lcrypt32 
	# LDFLAGS += -lgdi32 
	# LDFLAGS += -lws2_32 
else
    LDFLAGS += -lrt -lm
    LDFLAGS += -L$(LIB_DEF_PATH_STR)
    LDFLAGS += -L$(LIB_DEF_PATH_STR)/libcrypto/openssl_111b
    LDFLAGS += -L$(LIB_DEF_PATH_STR)/liblua/lua5.2
	LDFLAGS += -L$(LIB_DEF_PATH_STR)/libcurl/curl7.79.1
	LDFLAGS += -L$(LIB_DEF_PATH_STR)/libutf8
    
    LDFLAGS += -llua 
    LDFLAGS += -lcrypto 
    LDFLAGS += -lssl

	LDFLAGS += -lcurl
	LDFLAGS += -lutf8proc
endif #

LDFLAGS += -lz
#LDFLAGS += -lcurl

#
ifeq ($(PLATFORM),$(filter $(PLATFORM), win))
INC_DIR  += -I$(INC_DEF_PATH_STR) \
            -I$(INC_DEF_PATH_STR)/libcrypto/openssl_111a \
            -I$(INC_DEF_PATH_STR)/liblua/lua5.2 \
            -I$(INC_DEF_PATH_STR)/libcurl/curl7.79.1 \
            -I$(INC_DEF_PATH_STR)/libutf8
else
INC_DIR  += -I$(INC_DEF_PATH_STR) \
            -I$(INC_DEF_PATH_STR)/libcrypto/openssl_111b \
            -I$(INC_DEF_PATH_STR)/liblua/lua5.2 \
            -I$(INC_DEF_PATH_STR)/libcurl/curl7.79.1 \
            -I$(INC_DEF_PATH_STR)/libutf8
endif #


INC_DIR  += -I$(TRUNK_DIR)/inc \
            -I$(TRUNK_DIR)/inc/utils \
            -I$(TRUNK_DIR)/inc/curl \
            -I$(TRUNK_DIR)/inc/openssl \
            -I$(TRUNK_DIR)/inc/sec \
            -I$(TRUNK_DIR)/inc/lua 

EXTRA_CFLAGS += $(INC_DIR)

###############################################################
# Source Directory
###############################################################

ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
    SRCS = 
else
    SRCS += ../app/lua
endif #

SRCS += curl openssl sec lua utils

ifeq ($(PLATFORM),$(filter $(PLATFORM), linux))
    #
else
    SRCS += openssl/ms
endif #

#
define objs
    $(eval SRC_L := $(shell echo $(1)))
    $(eval SRC_U := $(shell echo $(SRC_L) | tr [a-z] [A-Z]))
    #$(eval SRC_$(SRC_U)_DIR ?= $(SRC_DIR)/$(SRC_L))
    $(eval SRCS_DIR += $(SRC_L))
    #$(eval OBJ_$(SRC_U)_DIR := $(SRC_$(SRC_U)_DIR))
    $(eval SRC_$(SRC_U)_CPP := $(wildcard $(SRC_$(SRC_U)_DIR)/*.cpp))
    $(eval SRCS_CPP += $(SRC_$(SRC_U)_CPP))
    #$(eval OBJS_CXX += $(patsubst $(SRC_$(SRC_U)_DIR)/%.cpp, $(OBJ_$(SRC_U)_DIR)/%.o, $(SRC_$(SRC_U)_CPP)))
    #$(eval DEPS_CXX += $(patsubst $(SRC_$(SRC_U)_DIR)/%.cpp, $(OBJ_$(SRC_U)_DIR)/%.d, $(SRC_$(SRC_U)_CPP)))
endef #

$(foreach src, $(SRCS) , $(eval $(call objs,$(src))))

###############################################################
# compile options
###############################################################

COMPILE_OBJ_NEW = yes

###################
# compile file list
###################

# main source
SRC_MAIN = 

# common library
SRC_LIB = $(SRCS_CPP)

# all compile source file list
LIBMODULE.TARGET = $(SRC_MAIN) $(SRC_LIB)

# compile meta-file to be in intermediate directory
LIBMODULE.INTERMEDIATE_DIR = $(OBJ_CFG_DIR)

# compile meta-file list (.obj, .d)
ifeq ($(COMPILE_OPT_NEW),$(filter $(COMPILE_OPT_NEW),yes))
    LIBMODULE.OBJ = $(subst $(SRC_DIR), $(LIBMODULE.INTERMEDIATE_DIR), $(LIBMODULE.TARGET:.cpp=.o))
    LIBMODULE.DEP = $(subst $(SRC_DIR), $(LIBMODULE.INTERMEDIATE_DIR), $(LIBMODULE.TARGET:.cpp=.d))
else
    LIBMODULE.OBJ = $(LIBMODULE.TARGET:.cpp=.o)
    LIBMODULE.DEP = $(LIBMODULE.TARGET:.cpp=.d)
endif #

###############################################################
# makefile process
###############################################################

.PHONY: debug release build clean rebuild PRE_BUILD POST_BUILD all

# make process scenario
BUILD_STEP = PRE_BUILD $(TARGET) POST_BUILD

# set makefile target and dependency
# to prevent "make: Nothing to be done for 'release'" warning,
# use @true keyword
ifeq ($(ARG.REBUILD),1)
    # under rebuild, do clean before build
    rebuild: | clean $(BUILD_STEP)
    debug: ; @true
    release: ; @true
else ifeq ($(ARG.CLEAN),1)
    # under clean, target has no rule to build
    release: ; @true
    debug: ; @true
else
    # under build release or debug, do build
    build: | $(BUILD_STEP)
    release: build
    debug: build
endif

ifeq ($(COMPILE_OBJ_NEW),$(filter $(COMPILE_OBJ_NEW),yes))
#######
# macro
#######

CONVERT_SRC   = $(subst $(LIBMODULE.INTERMEDIATE_DIR),$(SRC_DIR),$(@:.o=.cpp))
CONVERT_BUILD = $(subst $(SRC_DIR),$(LIBMODULE.INTERMEDIATE_DIR),$(@:.cpp=.o))

###########
# Link Part
###########

$(TARGET): BUILD_OBJD $(LIBMODULE.OBJ)
ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
#
else
	@echo ----------------------------------------
	@echo Link : $(TARGET)
	@echo ----------------------------------------
ifeq ($(MAKE_SO),$(filter $(MAKE_SO), yes))
	@$(CXX) $(LDFLAGS) $(LIBLINK) $(LIBMODULE.OBJ) -o $(TARGET) $(SYSROOT)
else
	@$(CXX) $(LIBLINK) $(LIBMODULE.OBJ) -o $(TARGET) $(SYSROOT) $(LDFLAGS)
endif #

endif #
	$(info)

##############
# Compile Part
##############
$(LIBMODULE.OBJ): %.o:
	@echo ----------------------------------------
	@echo Compile $(notdir $(CONVERT_SRC)) To $(notdir $(CONVERT_BUILD))
	@echo ----------------------------------------
	@mkdir -p $(@D)
	@$(CXX) -MM -MF $(@:.o=.d) -MT"$(@)" $(EXTRA_CFLAGS) $(CONVERT_SRC) $(SYSROOT)
	@$(CXX) $(EXTRA_CFLAGS) $(LIBCOMPILE) -c -o $@ $(CONVERT_SRC) $(SYSROOT)
ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
	@ar -rcus $(TARGET_LIB) $@ $^
endif #
	@$(info)

else #
###########
# Link Part
###########
$(TARGET): BUILD_OBJD $(LIBMODULE.OBJ) BUILD_CP_OBJ
	@echo ----------------------------------------
	@echo Link : $(TARGET)
	@echo ----------------------------------------
	@$(CXX) -o $(TARGET) $(LIBMODULE.OBJ) $(LDFLAGS)
	
##############
# Compile Part
##############
$(LIBMODULE.OBJ):%.o: %.cpp
	@echo ----------------------------------------
	@echo Compile : $(notdir $<)
	@echo ----------------------------------------
	$(CXX) -c $(EXTRA_CFLAGS) -o $@ $<

endif #

###################
# Pre-build process
###################

PRE_BUILD:
	@echo ================================================================
	@echo Make file started. config =\> $(CONFIG), platform =\> $(PLATFORM)
	@echo ================================================================

####################
# Post-build process
####################

# after release build, do strip command
POST_BUILD:
	@echo Post build...
ifeq ($(MAKE_SO),$(filter $(MAKE_SO), yes))
	@if [ "$(CONFIG)" = "release" ]; then \
		echo Start to strip; \
		echo $(STRIP) $(TARGET); \
		$(STRIP) $(TARGET); \
	fi;
endif #

ifeq ($(MAKE_A),$(filter $(MAKE_A), yes))
	@echo Compile completed : $(TARGET_LIB)
else
	@echo Compile completed : $(TARGET)
endif #
	@echo ================================================================
	@echo Make file finished. config =\> $(CONFIG), platform =\> $(PLATFORM)
	@echo ================================================================

BUILD_REPO:
	@$(call make-repo)

BUILD_OBJD:
	@$(call make-objd)

BUILD_CP_OBJ:
	@$(call cp-obj)

####################################
#
define make-objd
   mkdir -p $(OBJ_CFG_DIR);
   mkdir -p $(LIB_CFG_DIR);
endef

#
define make-repo
   for dir in $(SRCS_DIR); \
   do \
	mkdir -p $(OBJ_CFG_DIR)/$$dir; \
   done
endef

#
define cp-obj
   for objf in $(LIBMODULE.OBJ); \
   do \
	cp -rf $$objf $(OBJ_CFG_DIR)/; \
   done
endef
#######################################

##################
# Clean up process
##################
clean:
	@rm -f $(LIBMODULE.OBJ)
	@rm -f $(LIBMODULE.DEP)
	@rm -rf $(OBJ_DIR)
	@rm -rf $(LIB_DIR)
	@rm -f $(TARGET)
	@rm -f *~ core
	@echo -----------------------------------------------------------------
	@echo Clean work finished. config =\> $(CONFIG), platform =\> $(PLATFORM)
	@echo -----------------------------------------------------------------

ifeq ($(COMPILE_OBJ_NEW),$(filter $(COMPILE_OBJ_NEW),yes))
##########################
# Include dependency files
##########################
-include $(LIBMODULE.DEP)
endif #

