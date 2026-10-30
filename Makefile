SURICATA_SRC ?= ./suricata

CC       ?= gcc
CFLAGS   ?= -O2 -g -fPIC -Wall -Wextra
CPPFLAGS = -DHAVE_CONFIG_H -I$(SURICATA_SRC) -I$(SURICATA_SRC)/src

BUILD_DIR = build

SRCS = plugin.c runmode.c source.c eve.c
OBJS = $(addprefix $(BUILD_DIR)/,$(SRCS:.c=.o))

TARGET = $(BUILD_DIR)/mantis-capture.so

all: $(TARGET)

$(TARGET): $(OBJS)
	$(CC) -shared -o $@ $(OBJS)

$(BUILD_DIR)/%.o: %.c | $(BUILD_DIR)
	$(CC) $(CFLAGS) $(CPPFLAGS) "-D__SCFILENAME__=\"$(*F)\"" -c -o $@ $<

$(BUILD_DIR):
	mkdir -p $(BUILD_DIR)

clean:
	rm -rf $(BUILD_DIR)

.PHONY: all clean