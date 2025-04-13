# Credits

Craig Rowland - Inventor, Main developer and Maintainer of Portsentry from its inception in 1997 to its end in 2003

Thanks to the following people who offered testing and bug fixes/suggestions. I apologize if I've forgotten anyone. (No particular order on this list either):

Jeff Johnson <trn@flinet.com> - Initial tester. Recommended ipfwadm addition.

Ted Serreyn <tserreyn@serreyn.ml.org> - Initial tester and bug reports.

Les Fenison <les@cybcon.com> - Reported problems with logging of ignored hosts. 

Dave Andersen <angio@aros.net> - FreeBSD testing. ipfw syntax for 
configuration file.

Anonymous - HPUX testing and compile flags.

Superuser <root@triad.jadegate.com> - Lots of suggestions and general 
discussions...

Timothy Luoma <luomat@peak.org> - NeXT Step fixes/bug testing/various
suggestions and a really nice NeXTStep software archive (ftp.peak.org)!!

Marcus Butler <marcusb@wspice.com> - Sharing ideas, suggestions and
testing.

Forrest Aldrich <forrie@navinet.net> - FreeBSD testing and comments.

Drew Levandoski <drew.levandoski@nationsbank.com> - HPUX testing and compile
flags.

Yaron Yanay <yarony-cert@vipe.technion.ac.il> - Additional UDP ports to 
exclude in advanced mode.

Andrew Raphael <raphael@research.canon.com.au> - Binary and source RPMs.

Samuli Karkkainen <skarkkai@woods.iki.fi> - Helped in debugging Advanced mode
problem with SSH connection failures to Windows boxes.

System Administrator <phaeton@clubi.net> - Slackware testing and confirmation.

<mparson@smartnap.com> - Linux Alpha testing.

Alex Petrov <sysman@pd.gov.lv> - Lots of comments concerning code clean-up and
general efficiency recommendations.

Dmitry Prokhorov <dip@hq.bereg.net> - Patches to add $PORT$ token and fixes to
install scripts.

Rich Homolka <rich@stg.com> - Reported problem with binding over port 61000 for 
advanced mode was due to ip masquerading feature in Linux kernels.

Vesselin Atanasov <vesselin@bgnet.bg> - Patch to handle scan flooding
attacks (not included in this version for other reasons, but I thank him
for sending them in).

Lukasz Zalubski <chopin@ceti.com.pl> - Mirrored tools to Europe.

Matthias Lohmann <lohm@lynet.de> - Solaris porting and testing.

Don Bindner <dbindner@vh224401.truman.edu> - Found typo in UDP attack
logging that logged it as TCP attack.

Jon Coyle <jonco@sco.COM> - VERY helpful in testing for SCO. Also made up
HTML pages and man pages. I should be paying him!!

Brian D. Winters <brianw@alumni.caltech.edu> - Pointed out some compile
errors on various Linux platforms and submitted fixes. Also made
suggestions for areas of code cleanup. 

Jeremy T. Bouse <undrgrid@UnderGrid.net> - Made Debian packages of Sentry
as well as Debain init scripts and install scripts (not included yet).

Jeremy Hinegardner <jeremy@meru.cecs.missouri.edu> - Testing on SGI platforms.

Densin Roy. <den@ftp.loxinfo.co.th> - Suggested adding $PORT$ macro to command
execution.

<lburns@sasquatch.com> - NetBSD testing.

Dr. Stefan Demetrescu <stefand@xenon.stanford.edu> - Discussions concerning
the smart-verify timeout (or lack thereof) and recommendations on future
additions and fixes. 

Sean Amon <amon@cis.ohio-state.edu> - Solaris testing and fixes.

Eric Hines <hostmaster@galatia.com> - Solaris testing and fixes.

David LaPorte <david_laporte@harvard.edu> - Alpha Linux testing. Sent in
route drop command for new RedHat 6.0 systems (-reject flag).

Joshua Chamas <joshua@chamas.com> - Solaris testing.

Tom Briglia <Tom.Briglia@Corp.Sun.COM> - Solaris testing.

Roger Books <books@mail.state.fl.us> - Solaris testing and fixes.

Steven Walker <smw8923@zeus.olympus.cmsu.edu> - RedHat init scripts and RPMs.

Dominic J. Eidson <sauron@the-infinite.org> - AIX testing.

Christopher P. Lindsey <lindsey@mallorn.com> - Patch to get version 0.90
and below to work in stealth modes on older Linux systems/systems with
oddball tcpip.h files. Also helped in testing and debugging. Found bug in 
.ignore processing that wouldn't skip commented out lines. Contributed script 
to automatically setup ignore file on system startup by parsing ifconfig.
Found bug in ignore functions that would sometimes mis-compare IP's (also
lead me to find similar bug in isBlocked function).

Adrian <jimbud@arborlink.com> - Submitted bug report for 2.2.9 kernels with
respect to possible UDP struct change (dest vs. u_dport). 

Thomas Molina <tmolina@home.com> - Made binary and source RPMs for 0.90 of
PortSentry. 

Steve Marple <s.marple@lancaster.ac.uk> - Reported bug in commenting
out of .ignore file entries.

Graham Allan <ALLAN@mnhep1.hep.umn.edu> - Sent in compile options for 
Digital OSF Unix. Sent in route flags for same.

Ian Quick <ian@bork.org> - Sent in a fix for the ipchains rule to insert
blocks into filter list correctly.

Reuven Gevaryahu <gevaryah@netaxs.com> - Found a nasty bug where if
you setup to ignore either a tcp or a udp event an attacker could
activate the detector, cause the blocked file to be written to and
then activate the side you *wanted* the blocking to occur on and
have Sentry ignore them. A big thanks for finding this!

Jayakrishnan Krishnan <saljxk@tank.agl.uh.edu> - Reported the problem
on the latest build not ignoring hosts in the .ignore file.

Garth Brown <garthb@semaphore.com> - Also reported a problem with .blocked
file mis-reading blocked hosts and submitted a fix.

Morio Taneda <taneda@sozio.geist-soz.uni-karlsruhe.de> - Submitted a
*really cool* patch to use netlink with PortSentry. I'm sorry I didn't have 
time to implement this, but it is on my short list of fixes to put in after
1.0 is released. A big thanks for this!!

Howard Arons <hlarons@ComCAT.COM> - Suggested using LOCAL0 for possible syslog
configuration in config.h file.

Guido Guenther <guido.guenther@uni-konstanz.de> - Sent in bug fixes, Debian packages, comments, 
and many other contributions.

Christophe Rolland <crolland@freesurf.fr> - Wrote in to correct bug in .conf
file where I watched first 1025 ports instead of first 1024. Now advanced modes will watch
ports 1023 and below.

Ralf Hildebrandt <R.Hildebrandt@tu-bs.de> - Sent in route kill command for HPUX and fix
for GCC under HPUX for Makefile.

Graham Dunn <gdunn@inscriber.com> - Sent in KILL_ROUTE string for ipf filters.

Peter M. Allan <peter.m.allan@hsbcgroup.com> - Found an increment error in the host state engine
that could cause an error under certain configurations. Also contributed several fixes relating
to function usage and cosmetics.

Scott Catterton <scatterton@valinux.com> - Sent in new iptables support KILL_ROUTE command.

Dino A Amato <Dino.A.Amato@lerc.nasa.gov> - Sent in Makefile strings for Irix

Scott McCrory <scott@mccrory.com> - Sent in common DDOS daemon ports

Per J�nsson <pt98pjo@student.hk-r.se> - Sent in changes to allow for
ignoring networks/ports.

Flower <floweros@golia.ro> - Sent in request to disable DNS lookups.

Paul T. Kooros <kooros@titan.srrb.noaa.gov> - Sent in some code formatting issues that 
were resolved. 

Justin Pettit <jpettit@psionic.com> - Solaris fixes, proofreading, and lots of other stuff.
