HEADER = dnsdetect.h

default: dnsdetect

dnsdetect.o: dnsdetect.c $(HEADER)
	gcc -c -g  dnsdetect.c -lpcap -o dnsdetect.o
	
dnsdetect: dnsdetect.o
	gcc dnsdetect.o -lpcap -o dnsdetect

clean:
	-rm -f dnsdetect.o
	-rm -f dnsdetect
