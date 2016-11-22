CC		= g++
CFLAGS		= -std=c++11
LIBS		= -lcryptopp
SRC_EXT		= cpp

INC_DIR		= include
INC_FLAG	= -I$(INC_DIR)

SRC_DIR		= src
OBJ_DIR		= obj
BIN_DIR		= bin

TARGET_SHA	= $(BIN_DIR)/sha256
FILES_SHA	= sha256 sha256demo
SRC_SHA		= $(patsubst %, $(SRC_DIR)/%.$(SRC_EXT), $(FILES_SHA))
OBJ_SHA		= $(patsubst %, $(OBJ_DIR)/%.o, $(FILES_SHA))

TARGET_HMAC	= $(BIN_DIR)/hmac
FILES_HMAC	= sha256 hmac_sha256 hmacdemo
SRC_HMAC	= $(patsubst %, $(SRC_DIR)/%.$(SRC_EXT), $(FILES_HMAC))
OBJ_HMAC	= $(patsubst %, $(OBJ_DIR)/%.o, $(FILES_HMAC))

all: $(TARGET_SHA) $(TARGET_HMAC)

$(TARGET_SHA): $(OBJ_SHA)
	@mkdir -p $(@D)
	$(CC) $^ -o $@

$(TARGET_HMAC): $(OBJ_HMAC)
	@mkdir -p $(@D)
	$(CC) $^ -o $@ $(LIBS)

$(OBJ_DIR)/%.o: $(SRC_DIR)/%.$(SRC_EXT)
	@mkdir -p $(@D)
	$(CC) $(CFLAGS) $(INC_FLAG) -c -o $@ $<

demo: all
	$(TARGET_SHA) abc keyFile
	$(TARGET_HMAC) create keyFile messageFile outputFile
	$(TARGET_HMAC) verify keyFile messageFile outputFile

.PHONY: clean
clean:
	rm -rf *~ $(OBJ_DIR) $(BIN_DIR) keyFile outputFile
