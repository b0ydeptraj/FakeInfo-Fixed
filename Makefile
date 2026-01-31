ARCHS = arm64
TARGET := iphone:clang:latest:17.0
INSTALL_TARGET_PROCESSES = SpringBoard

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FakeInfo

FakeInfo_FILES = Tweak.xm
FakeInfo_CFLAGS = -fobjc-arc
FakeInfo_FRAMEWORKS = UIKit Foundation

include $(THEOS_MAKE_PATH)/tweak.mk
