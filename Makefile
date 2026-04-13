ARCHS = arm64
TARGET := iphone:clang:latest:17.0

export GO_EASY_ON_ME = 1

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SystemConfig

SystemConfig_FILES = Tweak.xm
SystemConfig_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable -Wno-arc-performSelector-leaks -Wno-incomplete-implementation
SystemConfig_FRAMEWORKS = UIKit Foundation Security CoreLocation CoreBluetooth CoreMotion AdSupport CoreTelephony SystemConfiguration
SystemConfig_PRIVATE_FRAMEWORKS = 
SystemConfig_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
