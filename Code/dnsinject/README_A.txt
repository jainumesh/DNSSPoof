Programing Language C
Library used: LIBPCAP
To run a file use command:
      dnsinject [-i interface] [-f hostnames] expression
    
    

Files Submitted:
1)dnsinject.c- source file
2)makefile
3)README: This file.
4)dnsinject.h -  header file
5_file.txt:  sample file for feeding hostnames
6)spoof-success.png : An example spoofing screenshot

Design: Reused mydump from HW2 to filter out DNS request packets.
        We keep a buffer with all ip details already filled up.
        Once a DNS request is sensed, the DNS header and body are populated and sent to the victim.
        DNS Query remains the same as in the request.
        The domain name in the DNS Query is isolated and matched against the set from file.
        DNS Answer is spoofed and the IP Address provided in the file<hostname> is added in DNS Answer.
        If file is not present we default to using "10.6.6.6" as the spoofed IP Address.
        We always keep a non-authorative response to keep response believeable.    
        
        
Sample file for input is placed in the folder. An attachent than includes successful spoofed attack to "www.hrtc.gov.in" is included.

Note about above: Even though Program is written in C, its not guaranteed to beat the server's response everytime, specially if the  response is cached in a nearby server(like stonybrook's proxy server)
However for non existent sites or the one whose DNS Server is far away spoofing is successful and GET request to spoofed IP is sent by the victim.(check attached screenshot)



