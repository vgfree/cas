include $(PWD)/config.mk
SRCDIR=src
INCDIR=include

ifeq ($(CAS_EXT_EXP),1)
DEFINES    = WI_AVAILABLE
endif

CC = gcc
CFLAGS = -g -Wall -fPIC -std=gnu99 -I${INCDIR}/ -I${SRCDIR}/ocf/env/ -I${SRCDIR}/ $(EXTRA_CFLAGS)
CFLAGS += -I./3api
CFLAGS += $(patsubst %,-D%,$(DEFINES))
LDFLAGS = -lsagocycas-external -lsagocycas-utils -lcomm -llogger -luuid -levcoro -lev -lpgalloc
LDFLAGS += -ldl -lc -lm -lz -pthread
LDFLAGS += -L./3api

libcas-c    = $(shell find ${SRCDIR} -name \*.c)
libcas-objs = $(patsubst $(SRCDIR)/%.c, .obj/%.o, $(libcas-c))

TARGET	     = example test

all: sync
	$(MAKE) $(TARGET)

example: libcas.a
	@echo "  LD " $@
	@$(CC) $(CFLAGS) tests/example.c -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive $(LDFLAGS)

test: libcas.a
	@echo "  LD " $@
	@$(CC) $(CFLAGS) tests/test.c -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive $(LDFLAGS)

libcas.a: $(libcas-objs)
	@echo "  AR " $@
	@ar rcs $@ $^
	@echo "  AR " libcas.a

.obj/%.o: $(PWD)/src/%.c
	@echo "  CC " $<
	@mkdir -p $(dir $@)
	@$(CC) -c $(CFLAGS) -MMD -MP -MF"$(@:%.o=%.d)" -MT"$(@:%.o=%.d)" -o "$@" "$<"

clean:
	@rm -rf ./libcas.a $(TARGET) $(libcas-objs)

distclean:
	make clean
	make distsync

.PHONY: all clean distclean
