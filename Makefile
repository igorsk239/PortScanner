#/*
# * File: 
# * Author: Igor Ignác xignac00@fit.vutbr.cz
# * Name: IPK project 2
# * Created: 
# * Faculty: Faculty of Information Technology, Brno University of Technology
# * Usage: make all -> compile whole project
# *				 make clean -> clean all object files and binaries
# *				 make compress -> creates xignac00.tar
#*/
CPP = g++
CPPFLAGS = -static-libstdc++ -Wextra -pedantic -g  -Wall 
NAME1 = ipk-scan
#NAME2 = ipk-server
#NAME3 = header

all:
		$(CPP) -o $(NAME1) $(NAME1).cpp $(CPPFLAGS)
#		$(CPP) -o $(NAME2) $(NAME2).cpp	$(CPPFLAGS)

#compress:
#		tar -cf xignac00.tar $(NAME1).cpp $(NAME2).cpp $(NAME3).h Makefile Readme xignac00.pdf
#		gzip xignac00.tar

clean:
		rm -f $(NAME1) *.o
