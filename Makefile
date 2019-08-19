LDFLAGS += -Wl,--no-as-needed
LDFLAGS += -lseccomp

seccomp: seccomp.o
	$(CC) $(LDFLAGS) -o $@ $^

.PHONY: clean
clean:
	rm -f *.o
	rm -f seccomp
