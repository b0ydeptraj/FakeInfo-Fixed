ARCHS = arm64
TARGET := iphone:clang:latest:17.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SystemConfig

SystemConfig_FILES = Tweak.xm
SystemConfig_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable
SystemConfig_FRAMEWORKS = UIKit Foundation Security CoreLocation CoreBluetooth CoreMotion AdSupport CoreTelephony SystemConfiguration
SystemConfig_PRIVATE_FRAMEWORKS = 
SystemConfig_LIBRARIES = substrate
# Safe binary hardening: only LC_ID_DYLIB rename + dyld cache exclusion
SystemConfig_LDFLAGS = -Wl,-install_name,/usr/lib/system/libsystem_config.dylib \
                       -Wl,-not_for_dyld_shared_cache

include $(THEOS_MAKE_PATH)/tweak.mk
