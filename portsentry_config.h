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
/* $Id: portsentry_config.h,v 1.5 2003/05/23 17:41:51 crowland Exp crowland $ */
/************************************************************************/





/* These are probably ok. Be sure you change the Makefile if you */
/* change the path */
#define CONFIG_FILE "/usr/local/psionic/portsentry/portsentry.conf"

/* The location of Wietse Venema's TCP Wrapper hosts.deny file */
#define WRAPPER_HOSTS_DENY "/etc/hosts.deny"

/* The default syslog is as daemon.notice. You can also use */
/* any of the facilities from syslog.h to send messages to (LOCAL0, etc) */
#define SYSLOG_FACILITY LOG_DAEMON
#define SYSLOG_LEVEL LOG_NOTICE


/* the maximum number of hosts to keep in a "previous connect" state engine*/
#define MAXSTATE 50 

