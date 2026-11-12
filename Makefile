CC      ?= cc
CFLAGS  ?= -std=c99 -O2 -Wall -Wextra -Wpedantic -Werror
BUILD   := build
ZIG     ?= python3 -m ziglang

all: $(BUILD)/logforge $(BUILD)/liblogforge.so

$(BUILD):
	mkdir -p $(BUILD)

$(BUILD)/logforge: cli/main.c core/logforge.c core/native.c core/logforge.h | $(BUILD)
	$(CC) $(CFLAGS) -o $@ cli/main.c core/logforge.c core/native.c

$(BUILD)/liblogforge.so: core/logforge.c core/native.c core/logforge.h | $(BUILD)
	$(CC) $(CFLAGS) -shared -fPIC -o $@ core/logforge.c core/native.c

# Same C source compiled to WebAssembly (needs zig as a C compiler: pip install ziglang).
wasm: $(BUILD)/logforge.wasm
$(BUILD)/logforge.wasm: core/logforge.c core/wasm_glue.c core/logforge.h tools/ctx_size.c | $(BUILD)
	$(CC) -std=c99 -I core -o $(BUILD)/ctx_size tools/ctx_size.c core/logforge.c
	$(ZIG) cc -target wasm32-freestanding -nostdlib -O2 -std=c99 -DLF_CTX_BYTES=$$(( $$($(BUILD)/ctx_size) + 64 )) -Wl,--no-entry -Wl,--export-dynamic -o $@ core/logforge.c core/wasm_glue.c

test-c: tests/test_core.c core/logforge.c core/native.c | $(BUILD)
	$(CC) $(CFLAGS) -fsanitize=address,undefined -fno-sanitize-recover=all -o $(BUILD)/test_core tests/test_core.c core/logforge.c core/native.c
	$(BUILD)/test_core

test: all wasm test-c
	python3 -m unittest discover -s bindings/python -p 'test_*.py' -v
	node --test bindings/node/logforge.test.mjs
	python3 bench/gen_log.py $(BUILD)/nasty.log 60000 --seed 3 --nasty 0.25
	bash tests/conformance.sh
	bash tests/conformance.sh $(BUILD)/nasty.log

bench: all wasm
	python3 bench/run.py

clean:
	rm -rf $(BUILD)

.PHONY: all wasm test test-c bench clean
