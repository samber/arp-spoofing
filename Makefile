
NAME = arpspoof

SRC = src/main.c src/arp.c src/socket.c src/if.c src/ethernet_ii.c src/datagram.c src/utils.c
OBJ = $(SRC:.c=.o)

CFLAGS = -W -Wall -Werror -Wextra -I ./include

all: $(NAME)

$(NAME): $(OBJ)
	$(CC) -o $(NAME) $(OBJ) ${CFLAGS}

clean:
	rm -rf $(OBJ)

fclean: clean
	rm -rf $(NAME)

re: fclean all
