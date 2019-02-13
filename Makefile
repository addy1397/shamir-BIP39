all: hello

hello: main.o sha256.o isss.o
	g++ main.o sha256.o isss.o -o hello

main.o: main.cpp
	g++ - c main.cpp

sha256.o: sha256.cpp
	g++ -c sha256.cpp

isss.o: isss.cpp
	g++ -c isss.cpp  

clean:
	rm -rf *o hello
	