/************************************************************************/
/*                                                                      */
/* PortSentry								*/
/*                                                                      */
/* Created: 10-12-1997                                                  */
/* Modified: 05-23-2003                                                 */
/*                                                                      */
/* Send all changes/modifications/bugfixes to:				*/
/* craigrowland at users dot sourceforge dot net    			*/
/*                                                                      */
/*                                                                      */
/* This software is Copyright(c) 1997-2003 Craig Rowland	        */
/*                                                                      */
/* This software is covered under the Common Public License v1.0	*/
/* See the enclosed LICENSE file for more information.			*/
/* $Id: portsentry.c,v 1.40 2003/05/23 17:41:25 crowland Exp crowland $ */
/************************************************************************/


#include "portsentry.h"
#include "portsentry_io.h"
#include "portsentry_util.h"

/* Global variables */
char gblScanDetectHost[MAXSTATE][IPMAXBUF];
char gblKillRoute[MAXBUF];
char gblKillHostsDeny[MAXBUF];
char gblKillRunCmd[MAXBUF];
char gblBlockedFile[MAXBUF];
char gblHistoryFile[MAXBUF];
char gblIgnoreFile[MAXBUF];
char gblDetectionType[MAXBUF];

int gblScanDetectCount = 0;
int gblBlockTCP = 0;
int gblBlockUDP = 0;
int gblRunCmdFirst = 0;
int gblResolveHost = 0;
int gblConfigTriggerCount = 0;

int
main (int argc, char *argv[])
{
  if (argc != 2)
    {
      Usage ();
      Exit (ERROR);
    }

  if ((geteuid ()) && (getuid ()) != 0)
    {
      printf ("You need to be root to run this.\n");
      Exit (ERROR);
    }


  /* Cheesy arg parser. Some systems don't support getopt and I don't want to port it. */
  if ((strcmp (argv[1], "-tcp")) && (strcmp (argv[1], "-udp"))
      && (strcmp (argv[1], "-stcp")) && (strcmp (argv[1], "-atcp"))
      && (strcmp (argv[1], "-sudp")) && (strcmp (argv[1], "-audp")) != 0)
    {
      Usage ();
      Exit (ERROR);
    }
  else
    {
      Start ();
      /* This copies the startup type to a global for later use */
      if ((SafeStrncpy (gblDetectionType, strstr (argv[1], "-") + 1, MAXBUF))
	  == NULL)
	{
	  Log("adminalert: ERROR: Error setting internal scan detection type.\n");
	  printf ("ERROR: Error setting internal scan detection type.\n");
	  printf ("ERROR: PortSentry is shutting down!\n");
	  Exit (ERROR);
	}
      else if (CheckConfig () == FALSE)
	{
	  Log ("adminalert: ERROR: Configuration files are missing/corrupted. Shutting down.\n");
	  printf ("ERROR: Configuration files are missing/corrupted.\n");
	  printf ("ERROR: Check your syslog for a more detailed error message.\n");
	  printf ("ERROR: PortSentry is shutting down!\n");
	  Exit (ERROR);
	}
      else if (InitConfig () == FALSE)
	{
	  Log ("adminalert: ERROR: Your config file is corrupted/missing mandatory option! Shutting down.\n");
	  printf ("ERROR: Your config file is corrupted/missing mandatory option!\n");
	  printf ("ERROR: Check your syslog for a more detailed error message.\n");
	  printf ("ERROR: PortSentry is shutting down!\n");
	  Exit (ERROR);
	}
#ifndef NODAEMON
      else if (DaemonSeed () == ERROR)
	{
	  Log ("adminalert: ERROR: could not go into daemon mode. Shutting down.\n");
	  printf ("ERROR: could not go into daemon mode. Shutting down.\n");
	  Exit (ERROR);
	}
#endif
    }


  if (strcmp (argv[1], "-tcp") == 0)
    {
      if (PortSentryModeTCP () == ERROR)
	{
	  Log ("adminalert: ERROR: could not go into PortSentry mode. Shutting down.\n");
	  Exit (ERROR);
	}
    }
#ifdef SUPPORT_STEALTH
  else if (strcmp (argv[1], "-stcp") == 0)
    {
      if (PortSentryStealthModeTCP () == ERROR)
	{
	  Log ("adminalert: ERROR: could not go into PortSentry mode. Shutting down.\n");
	  Exit (ERROR);
	}
    }
  else if (strcmp (argv[1], "-atcp") == 0)
    {
      if (PortSentryAdvancedStealthModeTCP () == ERROR)
	{
	  Log ("adminalert: ERROR: could not go into PortSentry mode. Shutting down.\n");
	  Exit (ERROR);
	}
    }
  else if (strcmp (argv[1], "-sudp") == 0)
    {
      if (PortSentryStealthModeUDP () == ERROR)
	{
	  Log ("adminalert: ERROR: could not go into PortSentry mode. Shutting down.\n");
	  Exit (ERROR);
	}
    }
  else if (strcmp (argv[1], "-audp") == 0)
    {
      if (PortSentryAdvancedStealthModeUDP () == ERROR)
	{
	  Log ("adminalert: ERROR: could not go into PortSentry mode. Shutting down.\n");
	  Exit (ERROR);
	}
    }
#endif
  else if (strcmp (argv[1], "-udp") == 0)
    {
      if (PortSentryModeUDP () == ERROR)
	{
	  Log ("adminalert: ERROR: could not go into PortSentry mode. Shutting down.\n");
	  Exit (ERROR);
	}
    }

  Exit (TRUE);
  /* shuts up compiler warning */
  return (0);
}

/****************************************************************/
/* Reads generic config options into global variables           */
/****************************************************************/
int
InitConfig (void)
{
  FILE *input;
  char configToken[MAXBUF];

  gblBlockTCP = CheckFlag ("BLOCK_TCP");
  gblBlockUDP = CheckFlag ("BLOCK_UDP");
  gblResolveHost = CheckFlag ("RESOLVE_HOST");

  memset (gblKillRoute, '\0', MAXBUF);
  memset (gblKillHostsDeny, '\0', MAXBUF);
  memset (gblKillRunCmd, '\0', MAXBUF);

  if ((ConfigTokenRetrieve ("SCAN_TRIGGER", configToken)) == FALSE)
    {
      Log ("adminalert: ERROR: Could not read SCAN_TRIGGER option from config file. Disabling SCAN DETECTION TRIGGER");
      gblConfigTriggerCount = 0;
    }
  else
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved SCAN_TRIGGER option: %s \n",
	   configToken);
#endif
      gblConfigTriggerCount = atoi (configToken);
    }

  if ((ConfigTokenRetrieve ("KILL_ROUTE", gblKillRoute)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved KILL_ROUTE option: %s \n",
	   gblKillRoute);
#endif
    }
  else
    {
#ifdef DEBUG
      Log ("debug: InitConfig: KILL_ROUTE option NOT FOUND.\n");
#endif
    }

  if ((ConfigTokenRetrieve ("KILL_HOSTS_DENY", gblKillHostsDeny)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved KILL_HOSTS_DENY option: %s \n",
	   gblKillHostsDeny);
#endif
    }
  else
    {
#ifdef DEBUG
      Log ("debug: InitConfig: KILL_HOSTS_DENY option NOT FOUND.\n");
#endif
    }

  if ((ConfigTokenRetrieve ("KILL_RUN_CMD", gblKillRunCmd)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved KILL_RUN_CMD option: %s \n",
	   gblKillRunCmd);
#endif
	/* Check the order we should run the KILL_RUN_CMD */
	/* Default is to run the command after blocking */
	gblRunCmdFirst = CheckFlag ("KILL_RUN_CMD_FIRST");
    }
  else
    {
#ifdef DEBUG
      Log ("debug: InitConfig: KILL_RUN_CMD option NOT FOUND.\n");
#endif
    }

  if ((ConfigTokenRetrieve ("BLOCKED_FILE", gblBlockedFile)) == TRUE)
    {
      if (strlen (gblBlockedFile) < MAXBUF - 5)
	{
	  strncat (gblBlockedFile, ".", 1);
	  strncat (gblBlockedFile, gblDetectionType, 4);
	}
      else
	{
	  Log ("adminalert: ERROR: Blocked filename is too long to append detection type file extension: %s.\n",
	     gblBlockedFile);
	  return (FALSE);
	}
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved BLOCKED_FILE option: %s \n",
	   gblBlockedFile);
      Log ("debug: CheckConfig: Removing old block file: %s \n",
	   gblBlockedFile);
#endif

      if ((input = fopen (gblBlockedFile, "w")) == NULL)
	{
	  Log
	    ("adminalert: ERROR: Cannot delete blocked file on startup: %s.\n",
	     gblBlockedFile);
	  return (FALSE);
	}
      else
	fclose (input);
    }
  else
    {
      Log ("InitConfig: Cannot retrieve BLOCKED_FILE option! Aborting\n");
      return (FALSE);
    }


  if ((ConfigTokenRetrieve ("HISTORY_FILE", gblHistoryFile)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved HISTORY_FILE option: %s \n",
	   gblHistoryFile);
#endif
    }
  else
    {
      Log ("InitConfig: Cannot retrieve HISTORY_FILE option! Aborting\n");
      return (FALSE);
    }

  if ((ConfigTokenRetrieve ("IGNORE_FILE", gblIgnoreFile)) == TRUE)
    {
#ifdef DEBUG
      Log ("debug: InitConfig: retrieved IGNORE_FILE option: %s \n",
	   gblIgnoreFile);
#endif
    }
  else
    {
      Log ("InitConfig: Cannot retrieve IGNORE_FILE option! Aborting\n");
      return (FALSE);
    }

  return (TRUE);
}


#ifdef SUPPORT_STEALTH

/* Read in a TCP packet taking into account IP options and other */
/* errors */
int
PacketReadTCP (int socket, struct iphdr *ipPtr, struct tcphdr *tcpPtr)
{
  char packetBuffer[TCPPACKETLEN];
  struct in_addr addr;

  bzero (ipPtr, sizeof (struct iphdr));
  bzero (tcpPtr, sizeof (struct tcphdr));

  if(read (socket, packetBuffer, TCPPACKETLEN) == ERROR)
    return(ERROR);

  memcpy (ipPtr, (struct iphdr *) packetBuffer, sizeof (struct iphdr));

  if ((ipPtr->ihl < 5) || (ipPtr->ihl > 15))
    {
      addr.s_addr = (u_int) ipPtr->saddr;
      Log ("attackalert: Illegal IP header length detected in TCP packet: %d from (possible) host: %s\n",
	 ipPtr->ihl, inet_ntoa (addr));
      return (FALSE);
    }
  else
    {
      memcpy (tcpPtr, (struct tcphdr *) (packetBuffer + ((ipPtr->ihl) * 4)),
	      sizeof (struct tcphdr));
      return (TRUE);
    }

}

/* Read in a UDP packet taking into account IP options and other */
/* errors */
int
PacketReadUDP (int socket, struct iphdr *ipPtr, struct udphdr *udpPtr)
{
  char packetBuffer[UDPPACKETLEN];
  struct in_addr addr;

  bzero (ipPtr, sizeof (struct iphdr));
  bzero (udpPtr, sizeof (struct udphdr));

  if(read (socket, packetBuffer, UDPPACKETLEN) == ERROR)
    return(ERROR);

  memcpy (ipPtr, (struct iphdr *) packetBuffer, sizeof (struct iphdr));

  if ((ipPtr->ihl < 5) || (ipPtr->ihl > 15))
    {
      addr.s_addr = (u_int) ipPtr->saddr;
      Log ("attackalert: Illegal IP header length detected in UDP packet: %d from (possible) host: %s\n",
	 ipPtr->ihl, inet_ntoa (addr));
      return (FALSE);
    }
  else
    {
      memcpy (udpPtr, (struct udphdr *) (packetBuffer + ((ipPtr->ihl) * 4)),
	      sizeof (struct udphdr));
      return (TRUE);
    }

}

/****************************************************************/
/* Stealth scan detection Mode One                              */
/*                                                              */
/* This mode will read in a list of ports to monitor and will   */
/* then open a raw socket to look for packets matching the port. */
/*                                                              */
/****************************************************************/
int
PortSentryStealthModeTCP (void)
{
  struct sockaddr_in client, server;
  int portCount = 0, portCount2 = 0, ports[MAXSOCKS], ports2[MAXSOCKS];
  int count = 0, scanDetectTrigger = TRUE, gotBound = FALSE, result = TRUE;
  int openSockfd = 0, incomingPort = 0;
  char *temp, target[IPMAXBUF], configToken[MAXBUF];
  char resolvedHost[DNSMAXBUF], *packetType;
  struct in_addr addr;
  struct iphdr ip;
  struct tcphdr tcp;

  if ((ConfigTokenRetrieve ("TCP_PORTS", configToken)) == FALSE)
    {
      Log ("adminalert: ERROR: Could not read TCP_PORTS option from config file");
      return (ERROR);
    }

  /* break out the ports */
  if ((temp = (char *) strtok (configToken, ",")) != NULL)
    {
      ports[0] = atoi (temp);
      for (count = 1; count < MAXSOCKS; count++)
	{
	  if ((temp = (char *) strtok (NULL, ",")) != NULL)
	    ports[count] = atoi (temp);
	  else
	    break;
	}
      portCount = count;
    }
  else
    {
      Log ("adminalert: ERROR: No TCP ports supplied in config file. Aborting");
      return (ERROR);
    }

  /* ok, now check if they have a network daemon on the socket already, if they do */
  /* then skip that port because it will cause false alarms */
  for (count = 0; count < portCount; count++)
    {
      Log ("adminalert: Going into stealth listen mode on TCP port: %d\n",
	   ports[count]);
      if ((openSockfd = OpenTCPSocket ()) == ERROR)
	{
	  Log ("adminalert: ERROR: could not open TCP socket. Aborting.\n");
	  return (ERROR);
	}

      if (BindSocket (openSockfd, client, server, ports[count]) == ERROR)
	Log ("adminalert: ERROR: Socket %d is in use and will not be monitored. Attempting to continue\n",
	   ports[count]);
      else /* well we at least bound to one socket so we'll continue */
	{
	  gotBound = TRUE;
	  ports2[portCount2++] = ports[count];
	}
      close (openSockfd);
    }

  /* if we didn't bind to anything then abort */
  if (gotBound == FALSE)
    {
      Log ("adminalert: ERROR: All supplied TCP sockets are in use and will not be listened to. Shutting down.\n");
      return (ERROR);
    }

  /* Open our raw socket for network IO */
  if ((openSockfd = OpenRAWTCPSocket ()) == ERROR)
    {
      Log ("adminalert: ERROR: could not open RAW TCP socket. Aborting.\n");
      return (ERROR);
    }

  Log ("adminalert: PortSentry is now active and listening.\n");

  /* main detection loop */
  for (;;)
    {
      if (PacketReadTCP (openSockfd, &ip, &tcp) != TRUE)
	continue;
      

      incomingPort = ntohs (tcp.dest);

      /* check for an ACK/RST to weed out established connections in case the user */
      /* is monitoring high ephemeral port numbers */
      if ((tcp.ack != 1) && (tcp.rst != 1))
	{
	  /* this iterates the list of ports looking for a match */
	  for (count = 0; count < portCount; count++)
	    {
	      if (incomingPort == ports2[count])
		{
		  if (SmartVerifyTCP (client, server, incomingPort) == TRUE)
		    break;

		  /* copy the clients address into our buffer for nuking */
		  addr.s_addr = (u_int) ip.saddr;
		  SafeStrncpy (target, (char *) inet_ntoa (addr), IPMAXBUF);
		  /* check if we should ignore this IP */
		  result = NeverBlock (target, gblIgnoreFile);

		  if (result == ERROR)
		    {
		      Log ("attackalert: ERROR: cannot open ignore file. Blocking host anyway.\n");
		      result = FALSE;
		    }

		  if (result == FALSE)
		    {
		      /* check if they've visited before */
		      scanDetectTrigger = CheckStateEngine (target);
		      if (scanDetectTrigger == TRUE)
			{
			if (gblResolveHost) /* Do they want DNS resolution? */
			{
				if(CleanAndResolve(resolvedHost, target) != TRUE)
				{
		      			Log ("attackalert: ERROR: Error resolving host. \
					      resolving disabled for this host.\n");
					snprintf (resolvedHost, DNSMAXBUF, "%s", target);
				}			
			}
			else
			{
				snprintf (resolvedHost, DNSMAXBUF, "%s", target);
			}

			  packetType = ReportPacketType (tcp);
			  Log ("attackalert: %s from host: %s/%s to TCP port: %d",
			     packetType, resolvedHost, target,
			     ports2[count]);
			  /* Report on options present */
			  if (ip.ihl > 5)
			    Log ("attackalert: Packet from host: %s/%s to TCP port: %d has IP options set (detection avoidance technique).",
			       resolvedHost, target, ports2[count]);

			  /* check if this target is already blocked */
			  if (IsBlocked (target, gblBlockedFile) == FALSE)
			    {
			      /* toast the prick */
			      if (DisposeTCP (target, ports2[count]) != TRUE)
				Log ("attackalert: ERROR: Could not block host %s/%s !!",
				   resolvedHost, target);
			      else
				WriteBlocked (target, resolvedHost,
					      ports2[count], gblBlockedFile,
					      gblHistoryFile, "TCP");
			    }	/* end IsBlocked check */
			  else
			    Log ("attackalert: Host: %s/%s is already blocked Ignoring",
			       resolvedHost, target);
			}	/* end if(scanDetectTrigger) */
		    }		/* end if(never block) check */
		  break;	/* get out of for(count) loop above */
		}		/* end if(incoming port) ==  protected port */
	    }			/* end for( check for protected port loop ) loop */
	}			/* end if(TH_ACK) check */
    }				/* end for( ; ; ) loop */

}				/* end PortSentryStealthModeTCP */


/****************************************************************/
/* Advanced Stealth scan detection Mode One                     */
/*                                                              */
/* This mode will see what ports are listening below 1024       */
/* and will then monitor all the rest. This is very sensitive   */
/* and will react on any packet hitting any monitored port,     */
/* regardless of TCP flags set                                  */
/*                                                              */
/****************************************************************/
int
PortSentryAdvancedStealthModeTCP (void)
{
  struct sockaddr_in client, server;
  int result = TRUE, scanDetectTrigger = TRUE, hotPort = TRUE;
  int openSockfd = 0, incomingPort = 0, smartVerify = FALSE;
  unsigned int advancedPorts = 1024;
  unsigned int count = 0, inUsePorts[MAXSOCKS], portCount = 0;
  char target[IPMAXBUF], configToken[MAXBUF];
  char resolvedHost[DNSMAXBUF], *temp, *packetType;
  struct in_addr addr;
  struct iphdr ip;
  struct tcphdr tcp;

  if ((ConfigTokenRetrieve ("ADVANCED_PORTS_TCP", configToken)) == FALSE)
    {
      Log ("adminalert: ERROR: Could not read ADVANCED_PORTS_TCP option from config file. Assuming 1024.");
      advancedPorts = 1024;
    }
  else
    advancedPorts = atoi (configToken);

  Log ("adminalert: Advanced mode will monitor first %d ports",
       advancedPorts);

  /* try to bind to all ports below 1024, any that are taken we exclude later */
  for (count = 0; count < advancedPorts; count++)
    {
      if ((openSockfd = OpenTCPSocket ()) == ERROR)
	{
	  Log ("adminalert: ERROR: could not open TCP socket. Aborting.\n");
	  return (ERROR);
	}
      if (BindSocket (openSockfd, client, server, count) == ERROR)
	inUsePorts[portCount++] = count;

      close (openSockfd);
    }

  if ((ConfigTokenRetrieve ("ADVANCED_EXCLUDE_TCP", configToken)) != FALSE)
    {
      /* break out the ports */
      if ((temp = (char *) strtok (configToken, ",")) != NULL)
	{
	  inUsePorts[portCount++] = atoi (temp);
	  Log ("adminalert: Advanced mode will manually exclude port: %d ",
	       inUsePorts[portCount - 1]);
	  for (count = 0; count < MAXSOCKS; count++)
	    {
	      if ((temp = (char *) strtok (NULL, ",")) != NULL)
		{
		  inUsePorts[portCount++] = atoi (temp);
		  Log ("adminalert: Advanced mode will manually exclude port: %d ",
		     inUsePorts[portCount - 1]);
		}
	      else
		break;
	    }
	}
    }
  else
    Log ("adminalert: Advanced mode will manually exclude no ports");


  for (count = 0; count < portCount; count++)
    Log ("adminalert: Advanced Stealth scan detection mode activated. Ignored TCP port: %d\n",
       inUsePorts[count]);

  /* open raw socket for reading */
  if ((openSockfd = OpenRAWTCPSocket ()) == ERROR)
    {
      Log ("adminalert: ERROR: could not open RAW TCP socket. Aborting.\n");
      return (ERROR);
    }

  Log ("adminalert: PortSentry is now active and listening.\n");

  /* main detection loop */
  for (;;)
    {
      if (PacketReadTCP (openSockfd, &ip, &tcp) != TRUE)
	continue;

      incomingPort = ntohs (tcp.dest);

      /* don't monitor packets with ACK set (established) or RST */
      /* This could be a hole in some cases */
      if ((tcp.ack != 1) && (tcp.rst != 1))
	{
	  /* check if we should ignore this connection to this port */
	  for (count = 0; count < portCount; count++)
	    {
	      if ((incomingPort == inUsePorts[count])
		  || (incomingPort >= advancedPorts))
		{
		  hotPort = FALSE;
		  break;
		}
	      else
		hotPort = TRUE;
	    }

	  if (hotPort)
	    {
	      smartVerify = SmartVerifyTCP (client, server, incomingPort);

	      if (smartVerify != TRUE)
		{
		  addr.s_addr = (u_int) ip.saddr;
		  SafeStrncpy (target, (char *) inet_ntoa (addr), IPMAXBUF);
		  /* check if we should ignore this IP */
		  result = NeverBlock (target, gblIgnoreFile);

		  if (result == ERROR)
		    {
		      Log ("attackalert: ERROR: cannot open ignore file. Blocking host anyway.\n");
		      result = FALSE;
		    }

		  if (result == FALSE)
		    {
		      /* check if they've visited before */
		      scanDetectTrigger = CheckStateEngine (target);

			if (scanDetectTrigger == TRUE)
			{
				if (gblResolveHost) /* Do they want DNS resolution? */
				{
					if(CleanAndResolve(resolvedHost, target) != TRUE)
					{
		      				Log ("attackalert: ERROR: Error resolving host. \
					      	resolving disabled for this host.\n");
						snprintf (resolvedHost, DNSMAXBUF, "%s", target);
					}			
				}
				else
				{
					snprintf (resolvedHost, DNSMAXBUF, "%s", target);
				}

			  packetType = ReportPacketType (tcp);
			  Log ("attackalert: %s from host: %s/%s to TCP port: %d",
			     packetType, resolvedHost, target, incomingPort);
			  /* Report on options present */
			  if (ip.ihl > 5)
			    Log ("attackalert: Packet from host: %s/%s to TCP port: %d has IP options set (detection avoidance technique).",
			       resolvedHost, target, incomingPort);

			  /* check if this target is already blocked */
			  if (IsBlocked (target, gblBlockedFile) == FALSE)
			    {
			      /* toast the prick */
			      if (DisposeTCP (target, incomingPort) != TRUE)
				Log ("attackalert: ERROR: Could not block host %s/%s!!",
				   resolvedHost, target);
			      else
				WriteBlocked (target, resolvedHost,
					      incomingPort, gblBlockedFile,
					      gblHistoryFile, "TCP");
			    }	/* end IsBlocked check */
			  else
			    Log ("attackalert: Host: %s/%s is already blocked Ignoring",
			       resolvedHost, target);
			}	/* end if(scanDetectTrigger) */
		    }		/* end if(never block) check */
		}		/* end if(smartVerify) */
	    }			/* end if(hotPort) */
	}			/* end if(TH_ACK) */
    }				/* end for( ; ; ) loop */
}
/* end PortSentryAdvancedStealthModeTCP */



/****************************************************************/
/* UDP "stealth" scan detection                                 */
/*                                                              */
/* This mode will read in a list of ports to monitor and will   */
/* then open a raw socket to look for packets matching the port. */
/*                                                              */
/****************************************************************/
int
PortSentryStealthModeUDP (void)
{
  struct sockaddr_in client, server;
  int portCount = 0, portCount2 = 0, ports[MAXSOCKS], ports2[MAXSOCKS],
    result = TRUE;
  int count = 0, scanDetectTrigger = TRUE, gotBound = FALSE;
  int openSockfd = 0, incomingPort = 0;
  char *temp, target[IPMAXBUF], configToken[MAXBUF];
  char resolvedHost[DNSMAXBUF];
  struct in_addr addr;
  struct iphdr ip;
  struct udphdr udp;


  if ((ConfigTokenRetrieve ("UDP_PORTS", configToken)) == FALSE)
    {
      Log ("adminalert: ERROR: Could not read UDP_PORTS option from config file");
      return (ERROR);
    }

  /* break out the ports */
  if ((temp = (char *) strtok (configToken, ",")) != NULL)
    {
      ports[0] = atoi (temp);
      for (count = 1; count < MAXSOCKS; count++)
	{
	  if ((temp = (char *) strtok (NULL, ",")) != NULL)
	    ports[count] = atoi (temp);
	  else
	    break;
	}
      portCount = count;
    }
  else
    {
      Log ("adminalert: ERROR: No UDP ports supplied in config file. Aborting");
      return (ERROR);
    }

  /* ok, now check if they have a network daemon on the socket already, if they do */
  /* then skip that port because it will cause false alarms */
  for (count = 0; count < portCount; count++)
    {
      Log ("adminalert: Going into stealth listen mode on UDP port: %d\n",
	   ports[count]);
      if ((openSockfd = OpenUDPSocket ()) == ERROR)
	{
	  Log ("adminalert: ERROR: could not open UDP socket. Aborting.\n");
	  return (ERROR);
	}

      if (BindSocket (openSockfd, client, server, ports[count]) == ERROR)
	Log ("adminalert: ERROR: Socket %d is in use and will not be monitored. Attempting to continue\n",
	   ports[count]);
      else
	{
	  gotBound = TRUE;
	  ports2[portCount2++] = ports[count];
	}
      close (openSockfd);
    }

  if (gotBound == FALSE)
    {
      Log ("adminalert: ERROR: All supplied UDP sockets are in use and will not be listened to. Shutting down.\n");
      return (ERROR);
    }

  if ((openSockfd = OpenRAWUDPSocket ()) == ERROR)
    {
      Log ("adminalert: ERROR: could not open RAW UDP socket. Aborting.\n");
      return (ERROR);
    }

  Log ("adminalert: PortSentry is now active and listening.\n");

  /* main detection loop */
  for (;;)
    {
      if (PacketReadUDP (openSockfd, &ip, &udp) != TRUE)
	continue;

      incomingPort = ntohs (udp.dest);

      /* this iterates the list of ports looking for a match */
      for (count = 0; count < portCount; count++)
	{
	  if (incomingPort == ports2[count])
	    {
	      if (SmartVerifyUDP (client, server, incomingPort) == TRUE)
		break;

	      addr.s_addr = (u_int) ip.saddr;
	      SafeStrncpy (target, (char *) inet_ntoa (addr), IPMAXBUF);
	      /* check if we should ignore this IP */
	      result = NeverBlock (target, gblIgnoreFile);

	      if (result == ERROR)
		{
		  Log ("attackalert: ERROR: cannot open ignore file. Blocking host anyway.\n");
		  result = FALSE;
		}

	      if (result == FALSE)
		{
		  /* check if they've visited before */
		  scanDetectTrigger = CheckStateEngine (target);
		  if (scanDetectTrigger == TRUE)
		    {
			if (gblResolveHost) /* Do they want DNS resolution? */
			{
				if(CleanAndResolve(resolvedHost, target) != TRUE)
				{
		      			Log ("attackalert: ERROR: Error resolving host. \
					resolving disabled for this host.\n");
					snprintf (resolvedHost, DNSMAXBUF, "%s", target);
				}			
			}
			else
			{
				snprintf (resolvedHost, DNSMAXBUF, "%s", target);
			}

		      Log ("attackalert: UDP scan from host: %s/%s to UDP port: %d",
			 resolvedHost, target, ports2[count]);
		      /* Report on options present */
		      if (ip.ihl > 5)
			Log ("attackalert: Packet from host: %s/%s to UDP port: %d has IP options set (detection avoidance technique).",
			       resolvedHost, target, incomingPort);

		      /* check if this target is already blocked */
		      if (IsBlocked (target, gblBlockedFile) == FALSE)
			{
			  if (DisposeUDP (target, ports2[count]) != TRUE)
			    Log ("attackalert: ERROR: Could not block host %s/%s!!",
			       resolvedHost, target);
			  else
			    WriteBlocked (target, resolvedHost, ports2[count],
					  gblBlockedFile, gblHistoryFile, "UDP");
			}	/* end IsBlocked check */
		      else
			{
			  Log ("attackalert: Host: %s/%s is already blocked Ignoring",
			     resolvedHost, target);
			}
		    }		/* end if(scanDetectTrigger) */
		}		/* end if(never block) check */
	      break;		/* get out of for(count) loop above */
	    }			/* end if(incoming port) ==  protected port */
	}			/* end for( check for protected port loop ) loop */
    }				/* end for( ; ; ) loop */

}				/* end PortSentryStealthModeUDP */


/****************************************************************/
/* Advanced Stealth scan detection mode for UDP                 */
/*                                                              */
/* This mode will see what ports are listening below 1024       */
/* and will then monitor all the rest. This is very sensitive   */
/* and will react on any packet hitting any monitored port.     */
/* This is a very dangerous option and is for advanced users    */
/*                                                              */
/****************************************************************/
int
PortSentryAdvancedStealthModeUDP (void)
{
  struct sockaddr_in client, server;
  int result = TRUE, scanDetectTrigger = TRUE, hotPort = TRUE;
  int openSockfd = 0, incomingPort = 0, smartVerify = FALSE;
  unsigned int advancedPorts = 1024;
  unsigned int count = 0, inUsePorts[MAXSOCKS], portCount = 0;
  char target[IPMAXBUF], configToken[MAXBUF];
  char resolvedHost[DNSMAXBUF], *temp;
  struct in_addr addr;
  struct iphdr ip;
  struct udphdr udp;


  if ((ConfigTokenRetrieve ("ADVANCED_PORTS_UDP", configToken)) == FALSE)
    {
      Log ("adminalert: ERROR: Could not read ADVANCED_PORTS_UDP option from config file. Assuming 1024.");
      advancedPorts = 1024;
    }
  else
    advancedPorts = atoi (configToken);

  Log ("adminalert: Advanced mode will monitor first %d ports",
       advancedPorts);

  /* try to bind to all ports below 1024, any that are taken we exclude later */
  for (count = 0; count < advancedPorts; count++)
    {
      if ((openSockfd = OpenUDPSocket ()) == ERROR)
	{
	  Log ("adminalert: ERROR: could not open UDP socket. Aborting.\n");
	  return (ERROR);
	}
      if (BindSocket (openSockfd, client, server, count) == ERROR)
	inUsePorts[portCount++] = count;

      close (openSockfd);
    }

  if ((ConfigTokenRetrieve ("ADVANCED_EXCLUDE_UDP", configToken)) != FALSE)
    {
      /* break out the ports */
      if ((temp = (char *) strtok (configToken, ",")) != NULL)
	{
	  inUsePorts[portCount++] = atoi (temp);
	  Log ("adminalert: Advanced mode will manually exclude port: %d ",
	       inUsePorts[portCount - 1]);
	  for (count = 0; count < MAXSOCKS; count++)
	    {
	      if ((temp = (char *) strtok (NULL, ",")) != NULL)
		{
		  inUsePorts[portCount++] = atoi (temp);
		  Log ("adminalert: Advanced mode will manually exclude port: %d ",
		     inUsePorts[portCount - 1]);
		}
	      else
		break;
	    }
	}
    }
  else
    Log ("adminalert: Advanced mode will manually exclude no ports");


  for (count = 0; count < portCount; count++)
    Log
      ("adminalert: Advanced Stealth scan detection mode activated. Ignored UDP port: %d\n",
       inUsePorts[count]);

  if ((openSockfd = OpenRAWUDPSocket ()) == ERROR)
    {
      Log ("adminalert: ERROR: could not open RAW UDP socket. Aborting.\n");
      return (ERROR);
    }

  Log ("adminalert: PortSentry is now active and listening.\n");

  /* main detection loop */
  for (;;)
    {
      if (PacketReadUDP (openSockfd, &ip, &udp) != TRUE)
	continue;

      incomingPort = ntohs (udp.dest);

      /* check if we should ignore this connection to this port */
      for (count = 0; count < portCount; count++)
	{
	  if ((incomingPort == inUsePorts[count])
	      || (incomingPort >= advancedPorts))
	    {
	      hotPort = FALSE;
	      break;
	    }
	  else
	    hotPort = TRUE;
	}

      if (hotPort)
	{
	  smartVerify = SmartVerifyUDP (client, server, incomingPort);

	  if (smartVerify != TRUE)
	    {
	      /* copy the clients address into our buffer for nuking */
	      addr.s_addr = (u_int) ip.saddr;
	      SafeStrncpy (target, (char *) inet_ntoa (addr), IPMAXBUF);
	      /* check if we should ignore this IP */
	      result = NeverBlock (target, gblIgnoreFile);

	      if (result == ERROR)
		{
		  Log ("attackalert: ERROR: cannot open ignore file. Blocking host anyway.\n");
		  result = FALSE;
		}

	      if (result == FALSE)
		{
		  /* check if they've visited before */
		  scanDetectTrigger = CheckStateEngine (target);

		  if (scanDetectTrigger == TRUE)
		    {
			if (gblResolveHost) /* Do they want DNS resolution? */
			{
				if(CleanAndResolve(resolvedHost, target) != TRUE)
				{
		      			Log ("attackalert: ERROR: Error resolving host. \
					resolving disabled for this host.\n");
					snprintf (resolvedHost, DNSMAXBUF, "%s", target);
				}			
			}
			else
			{
				snprintf (resolvedHost, DNSMAXBUF, "%s", target);
			}

		      Log ("attackalert: UDP scan from host: %s/%s to UDP port: %d",
			 resolvedHost, target, incomingPort);
		      /* Report on options present */
		      if (ip.ihl > 5)
			Log ("attackalert: Packet from host: %s/%s to UDP port: %d has IP options set (detection avoidance technique).",
			       resolvedHost, target, incomingPort);

		      /* check if this target is already blocked */
		      if (IsBlocked (target, gblBlockedFile) == FALSE)
			{
			  if (DisposeUDP (target, incomingPort) != TRUE)
			    Log ("attackalert: ERROR: Could not block host %s/%s!!",
			       resolvedHost, target);
			  else
			    WriteBlocked (target, resolvedHost, incomingPort,
					  gblBlockedFile, gblHistoryFile, "UDP");
			}	/* end IsBlocked check */
		      else
			Log ("attackalert: Host: %s/%s is already blocked Ignoring",
			   resolvedHost, target);
		    }		/* end if(scanDetectTrigger) */
		}		/* end if(never block) check */
	    }			/* end if (smartVerify) */
	}			/* end if(hotPort) */
    }				/* end for( ; ; ) loop */
}
/* end PortSentryAdvancedStealthModeUDP */

#endif




/****************************************************************/
/* Classic detection Mode                                       */
/*                                                              */
/* This mode will bind to a list of TCP sockets and wait for    */
/* connections to happen. Although the least prone to false     */
/* alarms, it also won't detect stealth scans                   */
/*                                                              */
/****************************************************************/
int
PortSentryModeTCP (void)
{

  struct sockaddr_in client, server;
  int length, portCount = 0, ports[MAXSOCKS];
  int openSockfd[MAXSOCKS], incomingSockfd, result = TRUE;
  int count = 0, scanDetectTrigger = TRUE, showBanner = FALSE, boundPortCount = 0;
  int selectResult = 0;
  char *temp, target[IPMAXBUF], bannerBuffer[MAXBUF], configToken[MAXBUF];
  char resolvedHost[DNSMAXBUF];
  fd_set selectFds;

  if ((ConfigTokenRetrieve ("TCP_PORTS", configToken)) == FALSE)
    {
      Log ("adminalert: ERROR: Could not read TCP_PORTS option from config file");
      return (ERROR);
    }

  /* break out the ports */
  if ((temp = (char *) strtok (configToken, ",")) != NULL)
    {
      ports[0] = atoi (temp);
      for (count = 1; count < MAXSOCKS; count++)
	{
	  if ((temp = (char *) strtok (NULL, ",")) != NULL)
	    ports[count] = atoi (temp);
	  else
	    break;
	}
      portCount = count;
    }
  else
    {
      Log ("adminalert: ERROR: No TCP ports supplied in config file. Aborting");
      return (ERROR);
    }

  /* read in the banner if one is given */
  if ((ConfigTokenRetrieve ("PORT_BANNER", configToken)) == TRUE)
    {
      showBanner = TRUE;
      SafeStrncpy (bannerBuffer, configToken, MAXBUF);
    }


  /* setup select call */
  FD_ZERO (&selectFds);

  for (count = 0; count < portCount; count++)
    {
      Log ("adminalert: Going into listen mode on TCP port: %d\n",
	   ports[count]);
      if ((openSockfd[boundPortCount] = OpenTCPSocket ()) == ERROR)
	{
	  Log ("adminalert: ERROR: could not open TCP socket. Aborting.\n");
	  return (ERROR);
	}

      if (BindSocket (openSockfd[boundPortCount], client, server, ports[count]) ==
	  ERROR)
	{
	  Log ("adminalert: ERROR: could not bind TCP socket: %d. Attempting to continue\n",
	     ports[count]);
	}
      else			/* well we at least bound to one socket so we'll continue */
	  boundPortCount++;
    }


  /* if we didn't bind to anything then abort */
  if (boundPortCount == 0)
    {
      Log ("adminalert: ERROR: could not bind ANY TCP sockets. Shutting down.\n");
      return (ERROR);
    }

  length = sizeof (client);

  Log ("adminalert: PortSentry is now active and listening.\n");

  /* main loop for multiplexing/resetting */
  for (;;)
    {
      /* set up select call */
      for (count = 0; count < boundPortCount; count++)
	FD_SET (openSockfd[count], &selectFds);
      selectResult =
	select (MAXSOCKS, &selectFds, NULL, NULL, (struct timeval *) NULL);

      /* something blew up */
      if (selectResult < 0)
	{
	  Log ("adminalert: ERROR: select call failed. Shutting down.\n");
	  return (ERROR);
	}
      else if (selectResult == 0)
	{
#ifdef DEBUG
	  Log ("Select timeout");
#endif
	}

      /* select is reporting a waiting socket. Poll them all to find out which */
      else if (selectResult > 0)
	{
	  for (count = 0; count < boundPortCount; count++)
	    {
	      if (FD_ISSET (openSockfd[count], &selectFds))
		{
		  incomingSockfd =
		    accept (openSockfd[count], (struct sockaddr *) &client,
			    &length);
		  if (incomingSockfd < 0)
		    {
		      Log ("attackalert: Possible stealth scan from unknown host to TCP port: %d (accept failed)",
			 ports[count]);
		      break;
		    }

		  /* copy the clients address into our buffer for nuking */
		  SafeStrncpy (target, (char *) inet_ntoa (client.sin_addr),
			       IPMAXBUF);
		  /* check if we should ignore this IP */
		  result = NeverBlock (target, gblIgnoreFile);

		  if (result == ERROR)
		    {
		      Log ("attackalert: ERROR: cannot open ignore file. Blocking host anyway.\n");
		      result = FALSE;
		    }

		  if (result == FALSE)
		    {
		      /* check if they've visited before */
		      scanDetectTrigger = CheckStateEngine (target);

		      if (scanDetectTrigger == TRUE)
			{
			  /* show the banner if one was selected */
			  if (showBanner == TRUE)
			    write (incomingSockfd, bannerBuffer,
				   strlen (bannerBuffer));
			  /* we don't need the bonehead anymore */
			  close (incomingSockfd);
			  if (gblResolveHost) /* Do they want DNS resolution? */
			  {
				if(CleanAndResolve(resolvedHost, target) != TRUE)
				{
		      			Log ("attackalert: ERROR: Error resolving host. \
					resolving disabled for this host.\n");
					snprintf (resolvedHost, DNSMAXBUF, "%s", target);
				}			
			  }
			  else
			  {
				snprintf (resolvedHost, DNSMAXBUF, "%s", target);
			  }

			  Log ("attackalert: Connect from host: %s/%s to TCP port: %d",
			     resolvedHost, target, ports[count]);

			  /* check if this target is already blocked */
			  if (IsBlocked (target, gblBlockedFile) == FALSE)
			    {
			      if (DisposeTCP (target, ports[count]) != TRUE)
				Log ("attackalert: ERROR: Could not block host %s !!",
				   target);
			      else
				WriteBlocked (target, resolvedHost,
					      ports[count], gblBlockedFile,
					      gblHistoryFile, "TCP");
			    }
			  else
			    Log ("attackalert: Host: %s is already blocked. Ignoring",
			       target);
			}
		    }
		  close (incomingSockfd);
		  break;
		}		/* end if(FD_ISSET) */
	    }			/* end for() */
	}			/* end else (selectResult > 0) */
    }				/* end main for(; ; ) loop */

/* not reached */
  close (incomingSockfd);
}





/****************************************************************/
/* Classic detection Mode                                       */
/*                                                              */
/* This mode will bind to a list of UDP sockets and wait for    */
/* connections to happen. Stealth scanning really doesn't apply */
/* here.                                                        */
/*                                                              */
/****************************************************************/
int
PortSentryModeUDP (void)
{
  struct sockaddr_in client, server;
  int length, ports[MAXSOCKS], openSockfd[MAXSOCKS], result = TRUE;
  int count = 0, portCount = 0, selectResult = 0, scanDetectTrigger = 0;
  int boundPortCount = 0, showBanner = FALSE;
  char *temp, target[IPMAXBUF], bannerBuffer[MAXBUF], configToken[MAXBUF];
  char buffer[MAXBUF];
  char resolvedHost[DNSMAXBUF];
  fd_set selectFds;

  if ((ConfigTokenRetrieve ("UDP_PORTS", configToken)) == FALSE)
    {
      Log ("adminalert: ERROR: Could not read UDP_PORTS option from config file");
      return (ERROR);
    }

  /* break out the ports */
  if ((temp = (char *) strtok (configToken, ",")) != NULL)
    {
      ports[0] = atoi (temp);
      for (count = 1; count < MAXSOCKS; count++)
	{
	  if ((temp = (char *) strtok (NULL, ",")) != NULL)
	    ports[count] = atoi (temp);
	  else
	    break;
	}
      portCount = count;
    }
  else
    {
      Log ("adminalert: ERROR: No UDP ports supplied in config file. Aborting");
      return (ERROR);
    }

  /* read in the banner if one is given */
  if ((ConfigTokenRetrieve ("PORT_BANNER", configToken)) == TRUE)
    {
      showBanner = TRUE;
      SafeStrncpy (bannerBuffer, configToken, MAXBUF);
    }

  /* setup select call */
  FD_ZERO (&selectFds);

  for (count = 0; count < portCount; count++)
    {
      Log ("adminalert: Going into listen mode on UDP port: %d\n",
	   ports[count]);
      if ((openSockfd[boundPortCount] = OpenUDPSocket ()) == ERROR)
	{
	  Log ("adminalert: ERROR: could not open UDP socket. Aborting\n");
	  return (ERROR);
	}
      if (BindSocket (openSockfd[boundPortCount], client, server, ports[count]) == ERROR)
	{
	  Log ("adminalert: ERROR: could not bind UDP socket: %d. Attempting to continue\n",
	     ports[count]);
	}
      else			/* well we at least bound to one socket so we'll continue */
	boundPortCount++;
    }

/* if we didn't bind to anything then abort */
  if (boundPortCount == 0)
    {
      Log ("adminalert: ERROR: could not bind ANY UDP sockets. Shutting down.\n");
      return (ERROR);
    }


  length = sizeof (client);
  Log ("adminalert: PortSentry is now active and listening.\n");

/* main loop for multiplexing/resetting */
  for (;;)
    {
      /* set up select call */
      for (count = 0; count < boundPortCount; count++)
	FD_SET (openSockfd[count], &selectFds);
      /* setup the select multiplexing (blocking mode) */
      selectResult =
	select (MAXSOCKS, &selectFds, NULL, NULL, (struct timeval *) NULL);

      if (selectResult < 0)
	{
	  Log ("adminalert: ERROR: select call failed. Shutting down.\n");
	  return (ERROR);
	}
      else if (selectResult == 0)
	{
#ifdef DEBUG
	  Log ("Select timeout");
#endif
	}

      /* select is reporting a waiting socket. Poll them all to find out which */
      else if (selectResult > 0)
	{
	  for (count = 0; count < portCount; count++)
	    {
	      if (FD_ISSET (openSockfd[count], &selectFds))
		{
		  /* here just read in one byte from the UDP socket, that's all we need to */
		  /* know that this person is a jerk */
		  if (recvfrom (openSockfd[count], buffer, 1, 0,
		       (struct sockaddr *) &client, &length) < 0)
		    {
		      Log ("adminalert: ERROR: could not accept incoming socket for UDP port: %d\n",
			 ports[count]);
		      break;
		    }

		  /* copy the clients address into our buffer for nuking */
		  SafeStrncpy (target, (char *) inet_ntoa (client.sin_addr),
			       IPMAXBUF);
#ifdef DEBUG
		  Log ("debug: PortSentryModeUDP: accepted UDP connection from: %s\n",
		     target);
#endif
		  /* check if we should ignore this IP */
		  result = NeverBlock (target, gblIgnoreFile);
		  if (result == ERROR)
		    {
		      Log ("attackalert: ERROR: cannot open ignore file. Blocking host anyway.\n");
		      result = FALSE;
		    }
		  if (result == FALSE)
		    {
		      /* check if they've visited before */
		      scanDetectTrigger = CheckStateEngine (target);
		      if (scanDetectTrigger == TRUE)
			{
			  /* show the banner if one was selected */
			  if (showBanner == TRUE)
			    sendto (openSockfd[count], bannerBuffer,
				    strlen (bannerBuffer), 0,
				    (struct sockaddr *) &client, length);

			  if (gblResolveHost) /* Do they want DNS resolution? */
			  {
				if(CleanAndResolve(resolvedHost, target) != TRUE)
				{
		      			Log ("attackalert: ERROR: Error resolving host. \
					resolving disabled for this host.\n");
					snprintf (resolvedHost, DNSMAXBUF, "%s", target);
				}			
			  }
			  else
			  {
				snprintf (resolvedHost, DNSMAXBUF, "%s", target);
			  }

			  Log
			    ("attackalert: Connect from host: %s/%s to UDP port: %d",
			     resolvedHost, target, ports[count]);
			  /* check if this target is already blocked */
			  if (IsBlocked (target, gblBlockedFile) == FALSE)
			    {
			      if (DisposeUDP (target, ports[count]) != TRUE)
				Log ("attackalert: ERROR: Could not block host %s !!",
				   target);
			      else
				WriteBlocked (target, resolvedHost,
					      ports[count], gblBlockedFile,
					      gblHistoryFile, "UDP");
			    }
			  else
			    Log ("attackalert: Host: %s is already blocked. Ignoring",
			       target);
			}
		    }
		  break;
		}		/* end if(FD_ISSET) */
	    }			/* end for() */
	}			/* end else (selectResult > 0) */
    }				/* end main for(; ; ) loop */

}				/* end UDP PortSentry */




/* kill the TCP connection depending on config option */
int
DisposeTCP (char *target, int port)
{
  int status = TRUE;

#ifdef DEBUG
  Log ("debug: DisposeTCP: disposing of host %s on port %d with option: %d",
       target, port, gblBlockTCP);
  Log ("debug: DisposeTCP: killRunCmd: %s", gblKillRunCmd);
  Log ("debug: DisposeTCP: gblRunCmdFirst: %d", gblRunCmdFirst);
  Log ("debug: DisposeTCP: killHostsDeny: %s", gblKillHostsDeny);
  Log ("debug: DisposeTCP: killRoute: %s  %d", gblKillRoute,
       strlen (gblKillRoute));
#endif
/* Should we ignore TCP from active response? */
  if (gblBlockTCP == 1)
    {
      /* run external command first, hosts.deny second, dead route last */
      if (gblRunCmdFirst)
	{
      	if (strlen (gblKillRunCmd) > 0)
		if (KillRunCmd (target, port, gblKillRunCmd, gblDetectionType) != TRUE)
	  		status = FALSE;
      	if (strlen (gblKillHostsDeny) > 0)
		if (KillHostsDeny (target, port, gblKillHostsDeny, gblDetectionType) != TRUE)
	  		status = FALSE;
      	if (strlen (gblKillRoute) > 0)
		if (KillRoute (target, port, gblKillRoute, gblDetectionType) != TRUE)
	  		status = FALSE;
	}
      /* run hosts.deny first, dead route second, external command last */
      else
	{
      	if (strlen (gblKillHostsDeny) > 0)
		if (KillHostsDeny (target, port, gblKillHostsDeny, gblDetectionType) != TRUE)
	  		status = FALSE;
      	if (strlen (gblKillRoute) > 0)
		if (KillRoute (target, port, gblKillRoute, gblDetectionType) != TRUE)
	  		status = FALSE;
      	if (strlen (gblKillRunCmd) > 0)
		if (KillRunCmd (target, port, gblKillRunCmd, gblDetectionType) != TRUE)
	  		status = FALSE;
	}
    }
  else if (gblBlockTCP == 2)
    {
      /* run external command only */
      if (strlen (gblKillRunCmd) > 0)
	if (KillRunCmd (target, port, gblKillRunCmd, gblDetectionType) != TRUE)
	  status = FALSE;
    }
  else
    Log ("attackalert: Ignoring TCP response per configuration file setting.");

  return (status);
}


/* kill the UDP connection depending on config option */
int
DisposeUDP (char *target, int port)
{
  int status = TRUE;

#ifdef DEBUG
  Log ("debug: DisposeUDP: disposing of host %s on port %d with option: %d",
       target, port, gblBlockUDP);
  Log ("debug: DisposeUDP: killRunCmd: %d", gblKillRunCmd);
  Log ("debug: DisposeUDP: gblRunCmdFirst: %s", gblRunCmdFirst);
  Log ("debug: DisposeUDP: killHostsDeny: %s", gblKillHostsDeny);
  Log ("debug: DisposeUDP: killRoute: %s  %d", gblKillRoute,
       strlen (gblKillRoute));
#endif
/* Should we ignore TCP from active response? */
  if (gblBlockUDP == 1)
    {	
      /* run external command first, hosts.deny second, dead route last */
      if (gblRunCmdFirst)
	{
      	if (strlen (gblKillRunCmd) > 0)
		if (KillRunCmd (target, port, gblKillRunCmd, gblDetectionType) != TRUE)
	  		status = FALSE;
      	if (strlen (gblKillHostsDeny) > 0)
		if (KillHostsDeny (target, port, gblKillHostsDeny, gblDetectionType) != TRUE)
	  		status = FALSE;
      	if (strlen (gblKillRoute) > 0)
		if (KillRoute (target, port, gblKillRoute, gblDetectionType) != TRUE)
	  		status = FALSE;
	}
      /* run hosts.deny first, dead route second, external command last */
      else
	{
      	if (strlen (gblKillHostsDeny) > 0)
		if (KillHostsDeny (target, port, gblKillHostsDeny, gblDetectionType) != TRUE)
	  		status = FALSE;
      	if (strlen (gblKillRoute) > 0)
		if (KillRoute (target, port, gblKillRoute, gblDetectionType) != TRUE)
	  		status = FALSE;
      	if (strlen (gblKillRunCmd) > 0)
		if (KillRunCmd (target, port, gblKillRunCmd, gblDetectionType) != TRUE)
	  		status = FALSE;
	}
    }
  else if (gblBlockUDP == 2)
    {
      /* run external command only */
      if (strlen (gblKillRunCmd) > 0)
	if (KillRunCmd (target, port, gblKillRunCmd, gblDetectionType) != TRUE)
	  status = FALSE;
    }
  else
    Log ("attackalert: Ignoring UDP response per configuration file setting.");

  return (status);
}


/* duh */
void
Usage (void)
{
  printf ("PortSentry - Port Scan Detector.\n");
  printf ("Copyright 1997-2003 Craig H. Rowland <craigrowland at users dot sourceforget dot net>\n");
  printf ("Licensing restrictions apply. Please see documentation\n");
  printf ("Version: %s\n\n", VERSION);
#ifdef SUPPORT_STEALTH
  printf ("usage: portsentry [-tcp -udp -stcp -atcp -sudp -audp]\n\n");
#else
  printf ("Stealth scan detection not supported on this platform\n");
  printf ("usage: portsentry [-tcp -udp]\n\n");
#endif
  printf ("*** PLEASE READ THE DOCS BEFORE USING *** \n\n");
}



/* our cheesy state engine to monitor who has connected here before */
int
CheckStateEngine (char *target)
{
  int count = 0, scanDetectTrigger = TRUE;
  int gotOne = 0;

/* This is the rather basic scan state engine. It maintains     */
/* an array of past hosts who triggered a connection on a port */
/* when a new host arrives it is compared against the array */
/* if it is found in the array it increments a state counter by */
/* one and checks the remainder of the array. It does this until */
/* the end is reached or the trigger value has been exceeded */
/* This would probably be better as a linked list/hash table, */
/* but for the number of hosts we are tracking this is just as good. */
/* This will probably change in the future */

  gotOne = 1;			/* our flag counter if we get a match */
  scanDetectTrigger = TRUE;	/* set to TRUE until set otherwise */

  if (gblConfigTriggerCount > 0)
    {
      for (count = 0; count < MAXSTATE; count++)
	{
	  /* if the array has the IP address then increment the gotOne counter and */
	  /* check the trigger value. If it is exceeded break out of the loop and */
	  /* set the detecttrigger to TRUE */
	  if (strcmp (gblScanDetectHost[count], target) == 0 )
	    {
	      /* compare the number of matches to the configured trigger value */
	      /* if we've exceeded we can stop this noise */
	      if (++gotOne >= gblConfigTriggerCount)
		{
		  scanDetectTrigger = TRUE;
#ifdef DEBUG
		  Log ("debug: CheckStateEngine: host: %s has exceeded trigger value: %d\n",
		     gblScanDetectHost[count], gblConfigTriggerCount);
#endif
		  break;
		}
	    }
	  else
	    scanDetectTrigger = FALSE;
	}

      /* now add the fresh meat into the state engine */
      /* if our array is still less than MAXSTATE large add it to the end */
      if (gblScanDetectCount < MAXSTATE)
	{
	  SafeStrncpy (gblScanDetectHost[gblScanDetectCount], target,
		       IPMAXBUF);
	  gblScanDetectCount++;
	}
      else
	{
	  /* otherwise tack it to the beginning and start overwriting older ones */
	  gblScanDetectCount = 0;
	  SafeStrncpy (gblScanDetectHost[gblScanDetectCount], target,
		       IPMAXBUF);
	  gblScanDetectCount++;
	}

#ifdef DEBUG
      for (count = 0; count < MAXSTATE; count++)
	Log ("debug: CheckStateEngine: state engine host: %s -> position: %d Detected: %d\n",
	   gblScanDetectHost[count], count, scanDetectTrigger);
#endif
      /* end catch to set state if gblConfigTriggerCount == 0 */
      if (gotOne >= gblConfigTriggerCount)
	scanDetectTrigger = TRUE;
    }


  if (gblConfigTriggerCount > MAXSTATE)
    {
      Log ("securityalert: WARNING: Trigger value %d is larger than state engine capacity of %d.\n",
	gblConfigTriggerCount);
      Log ("Adjust the value lower or recompile with a larger state engine value.\n",
	 MAXSTATE);
      Log ("securityalert: Blocking host anyway because of invalid trigger value");
      scanDetectTrigger = TRUE;
    }
  return (scanDetectTrigger);
}


#ifdef SUPPORT_STEALTH
/* This takes a tcp packet and reports what type of scan it is */
char *
ReportPacketType (struct tcphdr tcpPkt)
{
  static char packetDesc[MAXBUF];
  static char *packetDescPtr = packetDesc;

  if ((tcpPkt.syn == 0) && (tcpPkt.fin == 0) && (tcpPkt.ack == 0) \
      && (tcpPkt.psh == 0) && (tcpPkt.rst == 0) && (tcpPkt.urg == 0))
    snprintf (packetDesc, MAXBUF, " TCP NULL scan");
  else if ((tcpPkt.fin == 1) && (tcpPkt.urg == 1) && (tcpPkt.psh == 1))
    snprintf (packetDesc, MAXBUF, "TCP XMAS scan");
  else if ((tcpPkt.fin == 1) && (tcpPkt.syn != 1) && (tcpPkt.ack != 1) \
	   &&(tcpPkt.psh != 1) && (tcpPkt.rst != 1) && (tcpPkt.urg != 1))
    snprintf (packetDesc, MAXBUF, "TCP FIN scan");
  else if ((tcpPkt.syn == 1) && (tcpPkt.fin != 1) && (tcpPkt.ack != 1) \
	   &&(tcpPkt.psh != 1) && (tcpPkt.rst != 1) && (tcpPkt.urg != 1))
    snprintf (packetDesc, MAXBUF, "TCP SYN/Normal scan");
  else
    snprintf (packetDesc, MAXBUF,
	      "Unknown Type: TCP Packet Flags: SYN: %d FIN: %d ACK: %d PSH: %d URG: %d RST: %d", 
	      tcpPkt.syn, tcpPkt.fin, tcpPkt.ack, tcpPkt.psh, tcpPkt.urg,
	      tcpPkt.rst);

  return (packetDescPtr);
}

int
SmartVerifyTCP (struct sockaddr_in client, struct sockaddr_in server,
		int port)
{

  int testSockfd;

/* Ok here is where we "Smart-Verify" the socket. If the port was previously */
/* unbound, but now appears to have someone there, then we will skip responding */
/* to this inbound packet. This a basic "stateful" inspection of the */
/* the connection */

  if ((testSockfd = OpenTCPSocket ()) == ERROR)
    {
      Log ("adminalert: ERROR: could not open TCP socket to smart-verify.\n");
      return (FALSE);
    }
  else
    {
      if (BindSocket (testSockfd, client, server, port) == ERROR)
	{
#ifdef DEBUG
	  Log ("debug: SmartVerify: Smart-Verify Port In Use: %d", port);
#endif
	  close (testSockfd);
	  return (TRUE);
	}
    }

  close (testSockfd);
  return (FALSE);
}

int
SmartVerifyUDP (struct sockaddr_in client, struct sockaddr_in server,
		int port)
{
  int testSockfd;

/* Ok here is where we "Smart-Verify" the socket. If the port was previously */
/* unbound, but now appears to have someone there, then we will skip responding */
/* to this inbound packet. This essentially is a "stateful" inspection of the */
/* the connection */

  if ((testSockfd = OpenUDPSocket ()) == ERROR)
    {
      Log ("adminalert: ERROR: could not open UDP socket to smart-verify.\n");
      return (FALSE);
    }
  else
    {
      if (BindSocket (testSockfd, client, server, port) == ERROR)
	{
#ifdef DEBUG
	  Log ("debug: SmartVerify: Smart-Verify Port In Use: %d", port);
#endif
	  close (testSockfd);
	  return (TRUE);
	}
    }

  close (testSockfd);
  return (FALSE);
}

#endif /* SUPPORT_STEALTH */

