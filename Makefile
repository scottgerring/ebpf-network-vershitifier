all: vershitifier

clean:
	rm -f vershitifier
	rm -f bpf_x86_bpfel.go
	rm -f *.o

vershitifier: main.go bpf_x86_bpfel.o
	go build 

bpf_x86_bpfel.o: probes.c
	go generate
