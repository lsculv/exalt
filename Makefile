LIB_NAME=libexalt

SOURCE_DIR=src
HEADER_DIR=include
BUILD_DIR=target

OBJECTS=$(patsubst $(SOURCE_DIR)/%.c,%.o,$(wildcard $(SOURCE_DIR)/*.c))
OBJECTS += $(patsubst $(SOURCE_DIR)/%.S,%.o,$(wildcard $(SOURCE_DIR)/*.S))

RELEASE_DIR=$(BUILD_DIR)/release
DEBUG_DIR=$(BUILD_DIR)/debug

RELEASE_OBJECTS=$(addprefix $(RELEASE_DIR)/, $(OBJECTS))
DEBUG_OBJECTS=$(addprefix $(DEBUG_DIR)/, $(OBJECTS))

CFLAGS=-I $(HEADER_DIR) -nostdlib -nodefaultlibs \
	-Wall -Wextra -Wpedantic -Wformat=2 -Wformat-overflow=2 \
	-Wformat-truncation=2 -Wformat-security -Wnull-dereference \
	-Wstack-protector -Wtrampolines -Walloca -Wvla \
	-Warray-bounds=2 -Wdouble-promotion -Wshift-overflow=2 \
	-Wcast-qual -Wstringop-overflow=4 -Wconversion \
	-Wlogical-op -Wduplicated-cond -Wduplicated-branches \
	-Wformat-signedness -Wshadow -Wstrict-overflow=2 -Wundef \
	-Wstrict-prototypes -Wstack-usage=1000000 \
	-Wcast-align=strict -D_FORTIFY_SOURCE=3 -fstack-protector-strong \
	-fstack-clash-protection -fPIE -fsanitize=bounds \
	-fsanitize-undefined-trap-on-error -Wl,-z,relro -Wl,-z,now \
	-Wl,-z,noexecstack -Wl,-z,separate-code -fanalyzer
RELEASE_FLAGS=-O2
DEBUG_FLAGS=-ggdb

.PHONY: release debug
debug: DEBUG
release: RELEASE

.PHONY: all
all: release debug

define build_target
$1: $$($(1)_OBJECTS)
	ar rcs $$($1_DIR)/$(LIB_NAME).a $$^
endef

define build_object_c
$$($1_DIR)/%.o: $$(SOURCE_DIR)/%.c | $$($1_DIR)
	cc $$(CFLAGS) $$($1_FLAGS) -c $$< -o $$@
endef

define build_object_asm
$$($1_DIR)/%.o: $$(SOURCE_DIR)/%.S | $$($1_DIR)
	cc $$(CFLAGS) $$($1_FLAGS) -c $$< -o $$@
endef

$(eval $(call build_target,RELEASE))
$(eval $(call build_target,DEBUG))

$(eval $(call build_object_c,RELEASE))
$(eval $(call build_object_c,DEBUG))

$(eval $(call build_object_asm,RELEASE))
$(eval $(call build_object_asm,DEBUG))

$(RELEASE_DIR) $(DEBUG_DIR):
	mkdir -p $@

.PHONY: fmt
fmt:
	fd -e 'c' -e 'h' | xargs clang-format --verbose -i

.PHONY: clean
clean:
	rm -rf $(BUILD_DIR)
