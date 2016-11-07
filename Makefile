exe=gcc

OBJS=main.c arp.c

arp: $(OBJS)
	$(exe) -o $@ $(OBJS)

clean:
	-rm arp
