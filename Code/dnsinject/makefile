HEADER = dnsinject.h

default: dnsinject

dnsinject.o: dnsinject.c $(HEADER)
	gcc -c dnsinject.c -lpcap -o dnsinject.o
	
dnsinject: dnsinject.o
	gcc dnsinject.o -lpcap -o dnsinject

clean:
	-rm -f dnsinject.o
	-rm -f dnsinject
