PREFIX ?= /usr/local
DESTDIR ?=
APPID := org.nmapgtk.NmapGTK
ICON_SIZES := 16 24 32 48 64 128 256 512

BINDIR := $(DESTDIR)$(PREFIX)/bin
DATADIR := $(DESTDIR)$(PREFIX)/share

.PHONY: build install uninstall update-caches

build:
	cargo build --release

install: build
	install -Dm755 target/release/nmapgtk $(BINDIR)/nmapgtk
	install -Dm644 data/$(APPID).desktop $(DATADIR)/applications/$(APPID).desktop
	for s in $(ICON_SIZES); do \
		install -Dm644 data/icons/hicolor/$${s}x$${s}/apps/$(APPID).png \
			$(DATADIR)/icons/hicolor/$${s}x$${s}/apps/$(APPID).png; \
	done
	@$(MAKE) update-caches

uninstall:
	rm -f $(BINDIR)/nmapgtk
	rm -f $(DATADIR)/applications/$(APPID).desktop
	for s in $(ICON_SIZES); do \
		rm -f $(DATADIR)/icons/hicolor/$${s}x$${s}/apps/$(APPID).png; \
	done
	@$(MAKE) update-caches

# Refresh the icon and desktop caches (no-op failures are fine when not installing system-wide).
update-caches:
	-gtk-update-icon-cache -q -t -f $(DATADIR)/icons/hicolor 2>/dev/null || true
	-update-desktop-database -q $(DATADIR)/applications 2>/dev/null || true
