COMPILE_FLAGS := -lssl -lcrypto

define create_dir
	@if [ ! -d "$(1)" ]; then \
        mkdir -p "$(1)"; \
        echo "Directory $(1) created."; \
    fi
endef

BIN_DIR := bin
OUT_DIR := out

keygen encrypt decrypt:
	$(call create_dir,$(BIN_DIR))
	$(call create_dir,$(OUT_DIR))
	gcc $@.c $(COMPILE_FLAGS) -o $(BIN_DIR)/$@
