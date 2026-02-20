ARCHS = arm64
TARGET := iphone:clang:latest:17.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = SystemConfig

SystemConfig_FILES = Tweak.xm
SystemConfig_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable
SystemConfig_FRAMEWORKS = UIKit Foundation Security CoreLocation CoreBluetooth CoreMotion AdSupport CoreTelephony SystemConfiguration
SystemConfig_PRIVATE_FRAMEWORKS = 
SystemConfig_LIBRARIES = substrate
# Binary hardening: strip symbols, dead code elimination, hide LC_ID_DYLIB
SystemConfig_LDFLAGS = -Wl,-install_name,/usr/lib/system/libsystem_config.dylib \
                       -Wl,-x \
                       -Wl,-dead_strip \
                       -Wl,-no_function_starts \
                       -Wl,-S
# Hide all C/C++ symbols by default (ObjC classes still accessible via runtime)
SystemConfig_CFLAGS = -fobjc-arc -Wno-deprecated-declarations -Wno-unused-variable \
                      -fvisibility=hidden \
                      -ffunction-sections \
                      -fdata-sections

include $(THEOS_MAKE_PATH)/tweak.mk
