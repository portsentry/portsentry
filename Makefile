# Makefile for PortSentry package.
# 
# Send problems/code hacks to help@psionic.com 
#
#
# STEALTH MODE: Only works on Linux systems right now.
#
# The snprintf included with the package is for use with NEXTSTEP only,
# (Thanks Timothy <tjl@luomat.org>) although it may work elsewhere.
# We've not tried it under any other OS to date. It shouldn't be needed
# by any modern OS.
#
# Others have used the snprintf from:
#
# http://www.ijs.si/software/snprintf/
#
# We've not tried this yet but others have had good success. Our only 
# piece of advice for those running an OS without built in snprintf()
# is to upgrade. :)
#
#
# Generic compiler (usually linked to gcc on most platforms)
CC = cc

# GNU..
#CC = gcc 

# Normal systems flags
CFLAGS = -O -Wall -DNODAEMON

# Debug mode for portsentry
#CFLAGS = -Wall -g -DNODAEMON -DDEBUG
#CFLAGS = -Wall -g -DNODAEMON
#CFLAGS = -Wall -g -DDEBUG

# Profiler mode for portsentry
#CFLAGS = -pg -O -Wall -DNODAEMON
#LIBS = /usr/lib/libefence.a

INSTALLDIR = /usr/local/psionic
CHILDDIR=/portsentry

all:
		@echo "Usage: make <systype>"
		@echo "<systype> is one of: linux, debian-linux, bsd, solaris, hpux, hpux-gcc,"
		@echo "freebsd, osx, openbsd, netbsd, bsdi, aix, osf, irix, generic"
		@echo "" 
		@echo "This code requires snprintf()/vsnprintf() system calls"
		@echo "to work. If you run a modern OS it should work on"
		@echo "your system with 'make generic'. If you get it to"
		@echo "work on an unlisted OS please write us with the" 
		@echo "changes." 
		@echo "" 
		@echo "Install: make install"
		@echo "" 
		@echo "NOTE: This will install the package in this" 
		@echo "      directory: $(INSTALLDIR)" 
		@echo "" 
		@echo "Edit the makefile if you wish to change these paths." 
		@echo "Any existing files will be overwritten."

clean:		
		/bin/rm ./portsentry

uninstall:	
		/bin/rm $(INSTALLDIR)$(CHILDDIR)/*
		/bin/rmdir $(INSTALLDIR)

install:	
		@echo "Creating psionic directory $(INSTALLDIR)"
		@if [ ! -d $(INSTALLDIR) ]; then /bin/mkdir $(INSTALLDIR); fi
		@echo "Setting directory permissions"
		@if [ "$(INSTALLDIR)" = "/usr/local/psionic" ]; then /bin/chmod 700 $(INSTALLDIR) ; fi
		@echo "Creating portsentry directory $(INSTALLDIR)$(CHILDDIR)"
		@if [ ! -d $(INSTALLDIR)$(CHILDDIR) ]; then /bin/mkdir\
			$(INSTALLDIR)$(CHILDDIR); fi
		@echo "Setting directory permissions"
		chmod 700 $(INSTALLDIR)$(CHILDDIR)
		@echo "Copying files"
		cp ./portsentry.conf $(INSTALLDIR)$(CHILDDIR)
		cp ./portsentry.ignore $(INSTALLDIR)$(CHILDDIR)
		cp ./portsentry $(INSTALLDIR)$(CHILDDIR)
		@echo "Setting permissions"
		chmod 600 $(INSTALLDIR)$(CHILDDIR)/portsentry.ignore
		chmod 600 $(INSTALLDIR)$(CHILDDIR)/portsentry.conf
		chmod 700 $(INSTALLDIR)$(CHILDDIR)/portsentry
		@echo ""
		@echo ""
		@echo "Edit $(INSTALLDIR)$(CHILDDIR)/portsentry.conf and change"
		@echo "your settings if you haven't already. (route, etc)" 
		@echo ""
		@echo ""
		@echo "WARNING: This version and above now use a new"
		@echo "directory structure for storing the program"
		@echo "and config files ($(INSTALLDIR)$(CHILDDIR))."
		@echo "Please make sure you delete the old files when" 
		@echo "the testing of this install is complete."
		@echo ""
		@echo ""

linux:		
		SYSTYPE=linux 
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DLINUX -DSUPPORT_STEALTH -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c $(LIBS)

debian-linux:		
		SYSTYPE=debian-linux 
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DLINUX -DDEBIAN -DSUPPORT_STEALTH -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c $(LIBS)


bsd:		
		SYSTYPE=bsd
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c


openbsd:		
		SYSTYPE=openbsd
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c


freebsd:		
		SYSTYPE=freebsd
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c

osx:		
		SYSTYPE=osx
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c


netbsd:		
		SYSTYPE=netbsd
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c


bsdi:		
		SYSTYPE=bsdi
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DBSD44 -o ./portsentry ./portsentry.c \
		./portsentry_io.c ./portsentry_util.c


generic:		
		SYSTYPE=generic
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -o ./portsentry ./portsentry.c ./portsentry_io.c \
		./portsentry_util.c


hpux:		
		SYSTYPE=hpux
		@echo "Making $(SYSTYPE)"
		$(CC) -Ae -DHPUX -o ./portsentry ./portsentry.c ./portsentry_io.c \
		./portsentry_util.c


hpux-gcc:
		SYSTYPE=hpux-gcc
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -DHPUX -o ./portsentry ./portsentry.c ./portsentry_io.c \
		./portsentry_util.c 


solaris:		
		SYSTYPE=solaris
		@echo "Making $(SYSTYPE)"
		$(CC) -lnsl -lsocket -lresolv -lc -o ./portsentry ./portsentry.c ./portsentry_io.c \
		./portsentry_util.c


aix:		
		SYSTYPE=aix
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -o ./portsentry ./portsentry.c ./portsentry_io.c \
		./portsentry_util.c


osf:
		SYSTYPE=osf
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -taso -ldb -o ./portsentry ./portsentry.c ./portsentry_io.c \
		./portsentry_util.c 


irix:
		SYSTYPE=irix
		@echo "Making $(SYSTYPE)"
		$(CC) $(CFLAGS) -O -n32 -mips3 -o ./portsentry ./portsentry.c ./portsentry_io.c \
		./portsentry_util.c 


# NeXTSTEP Users. NeXT used to work, but we changed the log function and
# it now uses vsnprintf() to format strings. This means that this
# version does not work under NeXTSTEP until we can find a workable
# vsnprintf() call to put in the program. Sorry. If you have some good
# vsnprintf() code to use under NeXT please send it to us and we'll 
# include it on the next update.
#next:		
#		SYSTYPE=next
#		@echo "Making $(SYSTYPE)"
#		$(CC) $(CFLAGS) -DNEXT -DHAS_NO_SNPRINTF -posix -o ./portsentry ./portsentry.c \
#		./portsentry_io.c ./portsentry_util.c



