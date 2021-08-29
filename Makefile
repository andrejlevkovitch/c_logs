all: make_build_dir examples

make_build_dir:
	mkdir -p build

examples:
	gcc -o build/example_c   example/main.c   -Wall -Wextra -Wshadow -g -I./
	g++ -o build/example_cpp example/main.cpp -Wall -Wextra -Wshadow -g -I./
