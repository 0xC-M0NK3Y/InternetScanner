NAME = scanner
CC = gcc
CFLAGS = -Wall -Wextra -Werror
SRC = $(addprefix src/, main.c listenner.c packet.c utils.c)
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