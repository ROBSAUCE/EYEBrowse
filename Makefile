.PHONY: build dev run icon clean

build: dev icon
	rm -rf EyeBrowse.app
	mkdir -p EyeBrowse.app/Contents/MacOS
	mkdir -p EyeBrowse.app/Contents/Resources
	cp eyebrowse EyeBrowse.app/Contents/MacOS/eyebrowse
	chmod +x EyeBrowse.app/Contents/MacOS/eyebrowse
	cp icon.icns EyeBrowse.app/Contents/Resources/icon.icns
	cp Info.plist EyeBrowse.app/Contents/Info.plist
	touch EyeBrowse.app
	@# Re-register with Launch Services so macOS picks up the icon
	/System/Library/Frameworks/CoreServices.framework/Frameworks/LaunchServices.framework/Support/lsregister -f EyeBrowse.app 2>/dev/null || true

dev:
	CGO_LDFLAGS="-Wl,-no_warn_duplicate_libraries" go build -o eyebrowse .

run: build
	open EyeBrowse.app

icon:
	@if [ ! -f icon.icns ]; then \
		mkdir -p EyeBrowse.iconset; \
		sips -z 16 16 eyebrowse.png --out EyeBrowse.iconset/icon_16x16.png >/dev/null; \
		sips -z 32 32 eyebrowse.png --out EyeBrowse.iconset/icon_16x16@2x.png >/dev/null; \
		sips -z 32 32 eyebrowse.png --out EyeBrowse.iconset/icon_32x32.png >/dev/null; \
		sips -z 64 64 eyebrowse.png --out EyeBrowse.iconset/icon_32x32@2x.png >/dev/null; \
		sips -z 128 128 eyebrowse.png --out EyeBrowse.iconset/icon_128x128.png >/dev/null; \
		sips -z 256 256 eyebrowse.png --out EyeBrowse.iconset/icon_128x128@2x.png >/dev/null; \
		sips -z 256 256 eyebrowse.png --out EyeBrowse.iconset/icon_256x256.png >/dev/null; \
		sips -z 512 512 eyebrowse.png --out EyeBrowse.iconset/icon_256x256@2x.png >/dev/null; \
		sips -z 512 512 eyebrowse.png --out EyeBrowse.iconset/icon_512x512.png >/dev/null; \
		sips -z 1024 1024 eyebrowse.png --out EyeBrowse.iconset/icon_512x512@2x.png >/dev/null; \
		iconutil -c icns EyeBrowse.iconset -o icon.icns; \
		rm -rf EyeBrowse.iconset; \
	fi

clean:
	rm -f eyebrowse
	rm -f icon.icns
	rm -rf EyeBrowse.app
	rm -rf EyeBrowse.iconset
