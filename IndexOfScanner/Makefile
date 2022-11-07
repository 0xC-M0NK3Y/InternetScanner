NAME = IndexOfScanner
CC = gcc
CFLAGS = -Wall -Wextra -Werror -lcurl -lpthread -g
SRC = $(addprefix src/, main.c port_scanner_api.c utils.c)
OBJ = ${SRC:.c=.o}

all : ${NAME}

${NAME}: ${OBJ}
		${CC} ${OBJ} ${CFLAGS} -o ${NAME}

%.o: %.c
		${CC} -c ${<} -o ${@} ${CFLAGS}

clean:
		rm -rf ${OBJ}

fclean: clean
		rm -rf ${NAME}

re : fclean all