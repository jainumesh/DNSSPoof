Programing Language C
Library used: LIBPCAP
To run a file use command:
      dnsdetect  [-i interface] [-r tracefile] expression
    
Files Submitted:
1)dnsdetect.c- source file
2)makefile
3)README: This file.
4)dnsdetect.h -  header file
5)sample.pcap - sample tracefile
6)sample_output.txt- sample output on above tracefile generated from dnsinject tool

Design: Reused mydump from HW2 to filter out DNS response packets.
        Once a DNS response is sensed, its TX ID and answer IP Addresses are updated in a tuple
        It is then checked against the existing tuples to check if same TX ID matches with any existing entry
        If yes, and the IP Address received in this response is different from the previous tuple the program prints an alert on stdout
        
        
Sample.pcap is a sample trace file generated from dnsinject adn placed along with in the folder. sample_output.txt is the sample output generated when the sample.pcap is fed to dnsdetect




