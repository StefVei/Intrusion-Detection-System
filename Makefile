#Stefanos Veisakis csd3559@csd.uoc.gr
all: ids.c
	gcc -o ids ids.c -lpcap

clean:
		rm -rf ids