ARCHS = arm64 arm64e
TARGET := iphone:clang:latest:14.0
PACKAGE_VERSION = 1.0.0
THEOS_PACKAGE_SCHEME = rootless

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SystemConfig

SystemConfig_FILES = Tweak.xm
SystemConfig_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable
SystemConfig_FRAMEWORKS = UIKit Foundation Security CoreLocation CoreBluetooth CoreMotion AdSupport CoreTelephony SystemConfiguration
SystemConfig_PRIVATE_FRAMEWORKS = 
SystemConfig_LIBRARIES = substrate
# LC_ID_DYLIB override - ONLY safe flag for ObjC tweak
SystemConfig_LDFLAGS = -Wl,-install_name,/usr/lib/system/libsystem_config.dylib \
                       -Wl,-not_for_dyld_shared_cache

include $(THEOS_MAKE_PATH)/tweak.mk
