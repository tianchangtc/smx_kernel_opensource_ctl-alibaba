CC := gcc
CFLAGS += -I../ -g -D_GNU_SOURCE
BIN = provider
OBJ := $(patsubst %.c,%.o,$(wildcard *.c))

all: $(BIN)

$(BIN): $(OBJ)
	$(CC) $^ $(LIBS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) $< -c

clean:
	rm -f $(BIN) $(OBJ)

.PHONY: all clean $(BIN)
