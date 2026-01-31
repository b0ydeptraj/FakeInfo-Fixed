ARCHS = arm64
TARGET := iphone:clang:latest:17.0

include $(THEOS)/makefiles/common.mk

TWEAK_NAME = FakeInfo

FakeInfo_FILES = Tweak.xm
FakeInfo_CFLAGS = -fobjc-arc -Wno-deprecated-declarations
FakeInfo_FRAMEWORKS = UIKit Foundation Security
FakeInfo_PRIVATE_FRAMEWORKS = 
FakeInfo_LIBRARIES = substrate

include $(THEOS_MAKE_PATH)/tweak.mk
