include $(PWD)/config.mk
SRCDIR=src
INCDIR=include

CC = gcc
CFLAGS = -g -Wall -I${INCDIR}/ -I${SRCDIR}/ocf/env/ -I${SRCDIR}/ $(EXTRA_CFLAGS)
LDFLAGS = -lc -lm -lz -pthread

libcas-c    = $(shell find ${SRCDIR} -name \*.c)
libcas-objs = $(patsubst $(SRCDIR)/%.c, .obj/%.o, $(libcas-c))

TARGET	     = example

all: sync
	$(MAKE) $(TARGET)

$(TARGET): libcas.a
	@echo "  LD " $@
	@$(CC) $(CFLAGS) tests/example.c -o $@ -Wl,--whole-archive $^ -Wl,--no-whole-archive $(LDFLAGS)

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
