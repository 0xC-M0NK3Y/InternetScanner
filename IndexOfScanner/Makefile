NAME = bin/IndexOfScanner

CC = gcc
CFLAGS = -Wall -Wextra -Werror -lcurl -lpthread -g

SRC = $(wildcard src/*.c) $(wildcard src/*/*.c) $(wildcard src/*/*/*.c)
OBJ = $(addprefix build/, ${SRC:.c=.o})

all : ${NAME}

${NAME}: ${OBJ}
		${CC} ${OBJ} ${CFLAGS} -o ${NAME}

build/%.o: %.c
		mkdir -p $(shell dirname $@)
		${CC} -c $< -o $@ ${CFLAGS}

clean:
		rm -rf build/*

fclean: clean
		rm -rf ${NAME}

re : fclean all
