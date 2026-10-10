LOCAL_PATH := $(call my-dir)
include $(CLEAR_VARS)
LOCAL_MODULE := signet_io
LOCAL_SRC_FILES := deadline_io.c
LOCAL_CFLAGS := -Wall -Wextra -Werror -fstack-protector-strong
include $(BUILD_SHARED_LIBRARY)
