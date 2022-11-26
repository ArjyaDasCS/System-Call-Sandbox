arguments = main.o nodeStructure.o graphStructure.o reader.o systemcallhandler.o automataSimulation.o
a.out: main
	cp main a.out

main: $(arguments)

clean:
	rm $(arguments)