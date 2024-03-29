LOCAL_PATH:= $(call my-dir)
TDK_PATH:=../../tdk/
TA_BINARY=7ededcfe-b6e6-11e6-9cb0d4ae52a7b3b3
TA_CROSS_COMPILE=arm-linux-gnueabihf-
TA_EXPORT_DIR := out/target/product/$(TARGET_BOOTLOADER_BOARD_NAME)/system/lib/teetz

include $(CLEAR_VARS)

$(info $(shell make CROSS_COMPILE=$(TA_CROSS_COMPILE) -C $(LOCAL_PATH) TDK_DIR=$(TDK_PATH)))

$(info $(shell if [ ! -e $(TA_EXPORT_DIR) ]; then mkdir -p $(TA_EXPORT_DIR); fi))

ta_file := $(wildcard $(LOCAL_PATH)/*.ta)
ta_file := $(patsubst $(LOCAL_PATH)/%,%,$(ta_file))

$(info $(shell mkdir -p $(PRODUCT_OUT)/obj/lib))
$(info $(shell cp -vf $(LOCAL_PATH)/$(TA_BINARY).ta $(PRODUCT_OUT)/obj/lib))

LOCAL_MODULE := $(TA_BINARY)
LOCAL_SRC_FILES := $(ta_file)
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES
LOCAL_MODULE_SUFFIX := .ta
LOCAL_MODULE_PATH := $(PRODUCT_OUT)/system/lib/teetz
LOCAL_STRIP_MODULE := false
include $(BUILD_PREBUILT)

include $(CLEAR_VARS)
LOCAL_MODULE := tee_aes_gcm_ta
LOCAL_MODULE_TAGS := optional
LOCAL_MODULE_CLASS := SHARED_LIBRARIES

LOCAL_REQUIRED_MODULES := $(TA_BINARY)

include $(BUILD_PHONY_PACKAGE)
