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

CFLAGS=-Wall -Wextra -Werror -I $(HEADER_DIR)
RELEASE_FLAGS=-O2
DEBUG_FLAGS=-g

.PHONY: release debug
release: RELEASE
debug: DEBUG

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
