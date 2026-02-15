ARCHS = arm64
TARGET := iphone:clang:latest:17.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SystemConfig

SystemConfig_FILES = Tweak.xm
SystemConfig_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable
SystemConfig_FRAMEWORKS = UIKit Foundation Security CoreLocation CoreBluetooth CoreMotion AdSupport CoreTelephony SystemConfiguration
SystemConfig_PRIVATE_FRAMEWORKS = 
SystemConfig_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
