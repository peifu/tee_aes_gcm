################################################################################
# Android optee-hello-world makefile                                           #
################################################################################
LOCAL_PATH := $(call my-dir)

CFG_TEEC_PUBLIC_PATH = $(LOCAL_PATH)/../../tdk/ca_export_$(TARGET_ARCH)

################################################################################
# Build aes_gcm                                                                #
################################################################################
include $(CLEAR_VARS)
LOCAL_CFLAGS += -DANDROID_BUILD
LOCAL_CFLAGS += -Wall

LOCAL_SRC_FILES += aes_gcm.c

LOCAL_C_INCLUDES := $(LOCAL_PATH)/../ta/include \
		$(CFG_TEEC_PUBLIC_PATH)/include

LOCAL_SHARED_LIBRARIES := libteec
LOCAL_MODULE := tee_aes_gcm
LOCAL_MODULE_TAGS := optional
include $(BUILD_EXECUTABLE)
