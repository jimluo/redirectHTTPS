all:
	g++ eth_test.c ip_test.c tcp_test.c http_test.c main_test.c -lCppUTest -lCppUTestExt -o test

cover:
	g++ -fprofile-arcs -ftest-coverage http_test.c -lCppUTest -o test
	./test
	gcov test-sample.cpp -b

clean:
	rm -f test *.o *.gcov *.gcda *.gcno

install:
	apt install cppUTest