# siros-dc-matcher — UniFFI bindings, native packaging, and the matcher binary.
#
#   make matcher        — build matcher.wasm (the artifact wallets register)
#   make bindings       — generate Kotlin + Swift bindings
#   make android        — cross-compile the FFI library for Android
#   make aar            — package the Android AAR
#   make pom            — write the Maven POM for the AAR
#   make publish-local  — install AAR + POM into ~/.m2 for local Gradle builds
#   make check-bindings — fail if the committed bindings are stale
#   make clean

CRATE_NAME := siros_dc_matcher_ffi
LIB_NAME   := lib$(CRATE_NAME)
UNAME_S    := $(shell uname -s)
ifeq ($(UNAME_S),Darwin)
  HOST_LIB_EXT := dylib
else
  HOST_LIB_EXT := so
endif
VERSION := $(shell cargo metadata --no-deps --format-version 1 \
             | python3 -c "import sys,json; print(next(p['version'] for p in json.load(sys.stdin)['packages'] if p['name']=='siros-dc-matcher-ffi'))")

BUILD_DIR    := target
BINDINGS_DIR := bindings
SWIFT_DIR    := $(BINDINGS_DIR)/swift
KOTLIN_DIR   := $(BINDINGS_DIR)/kotlin
XCFRAMEWORK  := $(BUILD_DIR)/$(CRATE_NAME).xcframework

ANDROID_TARGETS := aarch64-linux-android armv7-linux-androideabi x86_64-linux-android
IOS_TARGETS     := aarch64-apple-ios
IOS_SIM_TARGETS := aarch64-apple-ios-sim x86_64-apple-ios
export IPHONEOS_DEPLOYMENT_TARGET ?= 16.0

.PHONY: all matcher bindings bindings-kotlin bindings-swift android aar pom \
        publish-local ios xcframework check-bindings clean

all: matcher bindings

# ── The matcher binary ───────────────────────────────────────────────

matcher:
	cargo build --locked -p siros-dc-matcher-wasm --target wasm32-wasip1 --release
	@ls -l $(BUILD_DIR)/wasm32-wasip1/release/matcher.wasm

# ── Binding generation ───────────────────────────────────────────────
#
# Generated from the built library rather than from source, which is how
# UniFFI discovers the interface. Note the profile: `strip = true` removes the
# metadata symbols UniFFI reads, and generation then produces nothing at all —
# no error, no files, exit code 0. The workspace profile strips debuginfo only
# for exactly this reason.

bindings: bindings-kotlin bindings-swift

bindings-kotlin: $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(KOTLIN_DIR)
	cargo run --locked -p siros-dc-matcher-ffi --features bindgen --bin uniffi-bindgen -- \
		generate --library $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language kotlin --out-dir $(KOTLIN_DIR)

bindings-swift: $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT)
	@mkdir -p $(SWIFT_DIR)
	cargo run --locked -p siros-dc-matcher-ffi --features bindgen --bin uniffi-bindgen -- \
		generate --library $(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT) \
		--language swift --out-dir $(SWIFT_DIR)

$(BUILD_DIR)/debug/$(LIB_NAME).$(HOST_LIB_EXT):
	cargo build --locked -p siros-dc-matcher-ffi

# ── Android ──────────────────────────────────────────────────────────

android: $(foreach t,$(ANDROID_TARGETS),android-$(t))

android-%:
	cargo ndk --target $* --platform 28 -- build --locked -p siros-dc-matcher-ffi --release

AAR_DIR := $(BUILD_DIR)/aar

aar: android
	@rm -rf $(AAR_DIR)
	@mkdir -p $(AAR_DIR)/jni/arm64-v8a $(AAR_DIR)/jni/armeabi-v7a $(AAR_DIR)/jni/x86_64
	cp $(BUILD_DIR)/aarch64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/arm64-v8a/
	cp $(BUILD_DIR)/armv7-linux-androideabi/release/$(LIB_NAME).so $(AAR_DIR)/jni/armeabi-v7a/
	cp $(BUILD_DIR)/x86_64-linux-android/release/$(LIB_NAME).so $(AAR_DIR)/jni/x86_64/
	@printf '%s' '<?xml version="1.0" encoding="utf-8"?><manifest xmlns:android="http://schemas.android.com/apk/res/android" package="org.siros.dcmatcher"/>' \
		> $(AAR_DIR)/AndroidManifest.xml
	# The matcher itself ships inside the AAR as an asset, so a wallet gets the
	# binary and the blob encoder from one dependency at one version. Shipping
	# them separately invites the pairing that silently matches nothing: a
	# CBOR-writing encoder and a matcher that predates it.
	@mkdir -p $(AAR_DIR)/assets
	$(MAKE) matcher
	cp $(BUILD_DIR)/wasm32-wasip1/release/matcher.wasm $(AAR_DIR)/assets/
	# Only native libraries and the asset ship here; the UniFFI Kotlin bindings
	# are consumed as vendored source, so an empty classes.jar (required by the
	# AAR layout) is enough. JNA arrives transitively via the POM.
	@rm -rf $(BUILD_DIR)/aar-classes
	@mkdir -p $(BUILD_DIR)/aar-classes/META-INF
	@printf 'Manifest-Version: 1.0\n' > $(BUILD_DIR)/aar-classes/META-INF/MANIFEST.MF
	cd $(BUILD_DIR)/aar-classes && zip -qr ../aar/classes.jar .
	cd $(AAR_DIR) && zip -qr ../$(CRATE_NAME)-$(VERSION).aar .
	@ls -l $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar

MAVEN_GROUP    := org.siros
MAVEN_ARTIFACT := siros-dc-matcher

pom:
	@mkdir -p $(BUILD_DIR)
	@printf '%s\n' \
	  '<?xml version="1.0" encoding="UTF-8"?>' \
	  '<project xmlns="http://maven.apache.org/POM/4.0.0"' \
	  '         xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance"' \
	  '         xsi:schemaLocation="http://maven.apache.org/POM/4.0.0 http://maven.apache.org/xsd/maven-4.0.0.xsd">' \
	  '  <modelVersion>4.0.0</modelVersion>' \
	  '  <groupId>$(MAVEN_GROUP)</groupId>' \
	  '  <artifactId>$(MAVEN_ARTIFACT)</artifactId>' \
	  '  <version>$(VERSION)</version>' \
	  '  <packaging>aar</packaging>' \
	  '  <dependencies>' \
	  '    <dependency>' \
	  '      <groupId>net.java.dev.jna</groupId>' \
	  '      <artifactId>jna</artifactId>' \
	  '      <version>5.14.0</version>' \
	  '      <type>aar</type>' \
	  '    </dependency>' \
	  '  </dependencies>' \
	  '</project>' \
	  > $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom

MAVEN_LOCAL_DIR := $(HOME)/.m2/repository/$(subst .,/,$(MAVEN_GROUP))/$(MAVEN_ARTIFACT)/$(VERSION)

publish-local: aar pom
	@mkdir -p $(MAVEN_LOCAL_DIR)
	cp $(BUILD_DIR)/$(CRATE_NAME)-$(VERSION).aar $(MAVEN_LOCAL_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).aar
	cp $(BUILD_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom $(MAVEN_LOCAL_DIR)/$(MAVEN_ARTIFACT)-$(VERSION).pom
	@echo "Installed org.siros:$(MAVEN_ARTIFACT):$(VERSION) to $(MAVEN_LOCAL_DIR)"

# ── iOS (Phase 7) ────────────────────────────────────────────────────

ios: $(foreach t,$(IOS_TARGETS) $(IOS_SIM_TARGETS),ios-$(t))

ios-%:
	cargo build --locked -p siros-dc-matcher-ffi --release --target $*

xcframework: ios bindings-swift
	@rm -rf $(XCFRAMEWORK)
	@mkdir -p $(BUILD_DIR)/ios-sim-universal
	lipo -create $(foreach t,$(IOS_SIM_TARGETS),$(BUILD_DIR)/$(t)/release/$(LIB_NAME).a) \
		-output $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a
	# Plain "module", not "framework module": this is built from static
	# archives, not real .framework bundles. Headers nest under a per-crate
	# directory because two static-archive XCFrameworks linked together
	# otherwise collide on a flat Headers/module.modulemap.
	@rm -rf $(BUILD_DIR)/Headers
	@mkdir -p $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI
	@cp $(SWIFT_DIR)/$(CRATE_NAME)FFI.h $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI/
	@echo "module $(CRATE_NAME)FFI { header \"$(CRATE_NAME)FFI.h\" export * }" \
		> $(BUILD_DIR)/Headers/$(CRATE_NAME)FFI/module.modulemap
	xcodebuild -create-xcframework \
		-library $(BUILD_DIR)/aarch64-apple-ios/release/$(LIB_NAME).a -headers $(BUILD_DIR)/Headers \
		-library $(BUILD_DIR)/ios-sim-universal/$(LIB_NAME).a -headers $(BUILD_DIR)/Headers \
		-output $(XCFRAMEWORK)

# ── CI helper ────────────────────────────────────────────────────────

check-bindings: bindings
	@git diff --exit-code $(BINDINGS_DIR) || \
		(echo "ERROR: committed bindings are stale. Run 'make bindings' and commit." && exit 1)

# Note what this does *not* remove: bindings/ is committed, because the Kotlin
# SDK vendors the generated .kt as source. Deleting it here would dirty the
# working tree and invite a commit of the deletions.
clean:
	cargo clean
