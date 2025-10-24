CC = gcc
SRC = ./src
OBJ = ./obj
LIB = ./lib
INC = ./inc
BIN = ./bin

CFLAGS = -Wall -Werror -std=c17
INCLUDE = -I $(INC) -L .

SRC_ALL = $(wildcard $(SRC)/*.c)
OBJ_ALL = $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRC_ALL))

SRCS_SERVER = $(wildcard $(SRC)/server*.c)   
OBJ_SERVER = $(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(SRCS_SERVER)) 

SRCS_JPARCE = $(wildcard $(SRC)/jparce*.c)   
OBJ_JPARCE = $(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(SRCS_JPARCE))

SRCS_ENCRYPT = $(wildcard $(SRC)/encrypt*.c)   
OBJ_ENCRYPT = $(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(SRCS_ENCRYPT))

SRCS_TEMP_SENSOR = $(wildcard $(SRC)/temperature_sensor*.c $(SRC)/broadcast.c)
OBJ_TEMP_SENSOR = $(patsubst $(SRC)/%.c,$(OBJ)/%.o,$(SRCS_TEMP_SENSOR))

SRCS_TCP = $(wildcard $(SRC)/packet.c $(SRC)/tcp*.c)
OBJ_TCP = $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS_TCP))

SRCS_LIGHT_CONTROLLER = $(wildcard $(SRC)/light_controller*.c $(SRC)/broadcast.c)
OBJ_LIGHT_CONTROLLER = $(patsubst $(SRC)/%.c, $(OBJ)/%.o, $(SRCS_LIGHT_CONTROLLER))

JPARCE_LIB = $(LIB)/libjparce.a
TCP_LIB = $(LIB)/tcp.a
ENCRYPT_LIB = $(LIB)/encrypt.a

SERVER = $(BIN)/server
TEMP_SENSOR = $(BIN)/temperature_sensor
LIGHT_CONTROLLER = $(BIN)/light_controller

all: $(JPARCE_LIB) $(TCP_LIB) $(SERVER) $(TEMP_SENSOR) $(LIGHT_CONTROLLER)

$(JPARCE_LIB): $(OBJ_JPARCE)
	ar rcs $@ $^

$(TCP_LIB): $(OBJ_TCP)
	ar rcs $@ $^

$(ENCRYPT_LIB): $(OBJ_ENCRYPT)
	ar rcs $@ $^

$(SERVER): $(OBJ_SERVER) $(JPARCE_LIB) $(TCP_LIB) $(ENCRYPT_LIB)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^

$(TEMP_SENSOR): $(OBJ_TEMP_SENSOR) $(JPARCE_LIB) $(ENCRYPT_LIB)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^

$(LIGHT_CONTROLLER): $(OBJ_LIGHT_CONTROLLER) $(JPARCE_LIB) $(TCP_LIB) $(ENCRYPT_LIB)
	$(CC) $(CFLAGS) $(INCLUDE) -o $@ $^

$(OBJ)/%.o: $(SRC)/%.c
	$(CC) $(CFLAGS) $(INCLUDE) -c $< -o $@ 

clean:
	rm -rf $(OBJ)/* $(LIB)/*
	rm -rf $(SERVER) $(TEMP_SENSOR) $(LIGHT_CONTROLLER)