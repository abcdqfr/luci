# KGE VPN Watchdog LuCI app. Enable/disable, run now, logs. Engine = ucode (ADR-0005).
# call BuildPackage (via luci.mk) - so OpenWrt feed scan discovers this package
include $(TOPDIR)/rules.mk

LUCI_TITLE:=KGE VPN Watchdog
LUCI_DEPENDS:=+luci-base +rpcd
LUCI_PKGARCH:=all

PKG_LICENSE:=GPL-2.0-only
PKG_MAINTAINER:=Brandon Hendershot <brandonhendershot@gmail.com>
PKG_RELEASE:=23

include ../../luci.mk
