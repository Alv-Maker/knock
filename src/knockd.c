/*
 *  knockd.c
 *
 *  Copyright (c) 2004-2012 by Judd Vinet <jvinet@zeroflux.org>
 *  Copyright (C) 2025 Alberto Novoa Gonzalez <angonzalez22@esei.uvigo.es>
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License along
 *  with this program; if not, write to the Free Software Foundation, Inc.,
 *  51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
 */

#if __APPLE__
/* In MacOSX 10.5+, the daemon function is deprecated and will give a warning.
 * This nasty hack which is used by Apple themselves in mDNSResponder does
 * the trick.
 */
#define daemon deprecated_in_osx_10_5_and_up
#endif

#include <stdio.h>
#include <stdlib.h>
#include <stdarg.h>
#include <unistd.h>
#include <signal.h>
#include <time.h>
#include <ctype.h>
#include <string.h>
#include <fcntl.h>
#include <limits.h>
#include <sys/socket.h>
#include <netinet/in_systm.h>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip6.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <net/if.h>
#include <netinet/if_ether.h>
#include <sys/types.h>
#include <sys/wait.h>
#include <sys/ioctl.h>
#include <arpa/inet.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <getopt.h>
#include <syslog.h>
#include <pcap.h>
#include <errno.h>
#include "list.h"
#include <openssl/sha.h>
#include <MQTTClient.h>

#if __APPLE__
#undef daemon
extern int daemon(int, int);
#endif

static char version[] = "0.9";

#define SEQ_TIMEOUT 25 /* default knock timeout in seconds */
#define CMD_TIMEOUT 10 /* default timeout in seconds between start and stop commands */
#define SEQ_MAX 32	   /* maximum number of ports in a knock sequence */

typedef enum _flag_stat
{
	DONT_CARE, /* 0 */
	SET,	   /* 1 */
	NOT_SET	   /* 2 */
} flag_stat;

/* knock/event tuples */
typedef struct opendoor
{
	char name[128];
	unsigned short seqcount;
	unsigned short sequence[SEQ_MAX];
	unsigned short protocol[SEQ_MAX];
	char *target;
	time_t seq_timeout;
	char *start_command;
	char *start_command6;
	time_t cmd_timeout;
	char *stop_command;
	char *stop_command6;
	flag_stat flag_fin;
	flag_stat flag_syn;
	flag_stat flag_rst;
	flag_stat flag_psh;
	flag_stat flag_ack;
	flag_stat flag_urg;
	FILE *one_time_sequences_fd;
	char *pcap_filter_exp;
	char *pcap_filter_expv6;
} opendoor_t;

/* The credentials that let you access knockd through MQTT */

typedef struct
{
	unsigned short sequence[SEQ_MAX];
	char anchorTopic[80];
	char sailerTopic[80];
	unsigned short *keySequence;
	unsigned short keySequenceCount;
	unsigned int MQTT_port;
	char *pcap_filter_exp;
	char *pcap_filter_expv6;

} credential_t;

PMList *doors = NULL;
PMList *credentials = NULL;
short tcp_port_tries = 0;

/* we keep one list of knock attempts per IP address,
 * and increment the stage as they progress through the sequence.
 */
typedef struct knocker
{
	opendoor_t *door;
	credential_t *cred;
	short stage;
	char src[64];  /* IP address */
	char *srchost; /* Hostname */
	time_t seq_start;
	int from_ipv6;
} knocker_t;
PMList *attempts = NULL;

/* function prototypes */
void dprint(char *fmt, ...);
void vprint(char *fmt, ...);
void logprint(char *fmt, ...);
void dprint_sequence(opendoor_t *door, char *fmt, ...);
void cleanup(int signum);
void child_exit(int signum);
void reload(int signum);
void ver();
void usage(int exit_code);
char *strtoupper(char *str);
char *trim(char *str);
void runCommand(char *cmd);
int parseconfig(char *configfile);
int parse_port_sequence(char *sequence, opendoor_t *door);
void generate_pcap_filter();
size_t realloc_strcat(char **dest, const char *src, size_t size);
void free_door(opendoor_t *door);
void close_door(opendoor_t *door);
char *get_ip(const char *iface, char *buf, int bufsize);
size_t parse_cmd(char *dest, size_t size, const char *command, const char *src);
int exec_cmd(char *command, char *name);
void sniff(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *packet);
int target_strcmp(char *ip, char *target);
void secondPhaseManager(knocker_t *sealer);
credential_t *generate_new_credentials();
unsigned short *receive_sequence(char *topic, unsigned int port);
// void register_new_sequence(const unsigned char *command, unsigned short *sequence);
void generate_new_sequence();
void search_and_exec(unsigned short *sequence, char* sailerIP);

pcap_t *cap = NULL;
FILE *logfd = NULL;
int lltype = -1;
int has_ipv4 = 0;
int has_ipv6 = 0;
/* list of IP addresses for given interface
 */
typedef struct ip_literal
{
	struct ip_literal *next;
	char *value;
	int is_ipv6;
} ip_literal_t;
ip_literal_t *myips = NULL;

int o_usesyslog = 0;
int o_verbose = 0;
int o_debug = 0;
int o_daemon = 0;
int o_lookup = 0;
int o_skipIpV6 = 0;
char o_int[32] = ""; /* default (eth0) is set after parseconfig() */
char o_cfg[PATH_MAX] = "/etc/knockd.conf";
char o_pidfile[PATH_MAX] = "/var/run/knockd.pid";
char o_logfile[PATH_MAX] = "";

int main(int argc, char **argv)
{
	struct ifaddrs *ifaddr, *ifa;
	ip_literal_t *myip;
	char pcap_err[PCAP_ERRBUF_SIZE] = "";
	int opt, ret, optidx = 1;

	unsigned int *sequence = NULL;

	static struct option opts[] =
		{
			{"verbose", no_argument, 0, 'v'},
			{"debug", no_argument, 0, 'D'},
			{"daemon", no_argument, 0, 'd'},
			{"lookup", no_argument, 0, 'l'},
			{"interface", required_argument, 0, 'i'},
			{"config", required_argument, 0, 'c'},
			{"help", no_argument, 0, 'h'},
			{"pidfile", required_argument, 0, 'p'},
			{"logfile", required_argument, 0, 'g'},
			{"only-ip-v4", no_argument, 0, '4'},
			{"version", no_argument, 0, 'V'},
			{0, 0, 0, 0}};

	printf("knockd %s\n", version);


	credential_t* cred = generate_new_credentials();

	credentials = list_add(credentials, cred);

	FILE* seq_file = fopen("seq.conf", "w");
	if (seq_file == NULL)
	{
		perror("Failed to open seq.conf for writing");
		exit(1);
	}
	for(int i = 0; i < cred->keySequenceCount; i++)
	{
		fprintf(seq_file, "%hu\n", cred->keySequence[i]);
	}
	fprintf(seq_file, "0\n"); // End of sequence marker
	fprintf(seq_file, "%s\n", cred->anchorTopic);
	fprintf(seq_file, "%s\n", cred->sailerTopic);
	fprintf(seq_file, "%d\n", cred->MQTT_port);
	fclose(seq_file);

	while ((opt = getopt_long(argc, argv, "4vDdli:c:p:g:hV", opts, &optidx)))
	{
		if (opt < 0)
		{
			break;
		}
		switch (opt)
		{
		case 0:
			break;
		case 'v':
			o_verbose = 1;
			break;
		case 'D':
			o_debug = 1;
			break;
		case 'd':
			o_daemon = 1;
			break;
		case 'l':
			o_lookup = 1;
			break;
		case '4':
			o_skipIpV6 = 1;
			break;
		case 'i':
			strncpy(o_int, optarg, sizeof(o_int) - 1);
			o_int[sizeof(o_int) - 1] = '\0';
			break;
		case 'c':
			strncpy(o_cfg, optarg, sizeof(o_cfg) - 1);
			o_cfg[sizeof(o_cfg) - 1] = '\0';
			break;
		case 'p':
			strncpy(o_pidfile, optarg, sizeof(o_pidfile) - 1);
			o_pidfile[sizeof(o_pidfile) - 1] = '\0';
			break;
		case 'g':
			strncpy(o_logfile, optarg, sizeof(o_logfile) - 1);
			o_logfile[sizeof(o_logfile) - 1] = '\0';
			break;
		case 'V':
			ver();
		case 'h': /* fallthrough */
		default:
			usage(0);
		}
	}

	if (parseconfig(o_cfg))
	{
		usage(1);
	}

	/* set o_int to a default value if it has not been set by the -i switch nor by
	 * the config file */
	if (strlen(o_int) == 0)
	{
		strncpy(o_int, "eth0", sizeof(o_int)); /* no explicit termination needed */
	}
	if (o_usesyslog)
	{
		openlog("knockd", 0, LOG_USER);
	}
	if (strlen(o_logfile))
	{
		/* open the log file */
		logfd = fopen(o_logfile, "a");
		if (logfd == NULL)
		{
			perror("warning: cannot open logfile");
		}
	}

	/* 50ms timeout for packet capture. See pcap(3pcap) manpage, which
	 * recommends that a timeout of 0 not be used. */
	cap = pcap_open_live(o_int, 65535, 0, 50, pcap_err);
	if (strlen(pcap_err))
	{
		fprintf(stderr, "could not open %s: %s\n", o_int, pcap_err);
	}
	if (cap == NULL)
	{
		exit(1);
	}

	lltype = pcap_datalink(cap);
	switch (lltype)
	{
	case DLT_EN10MB:
		dprint("ethernet interface detected\n");
		break;
#ifdef __linux__
	case DLT_LINUX_SLL:
		dprint("ppp interface detected (linux \"cooked\" encapsulation)\n");
		break;
#endif
	case DLT_RAW:
		dprint("raw interface detected, no encapsulation\n");
		break;
	default:
		fprintf(stderr, "error: unsupported link-layer type: %d\n", lltype);
		cleanup(1);
		break;
	}

	/* get our local IP addresses */
	if (getifaddrs(&ifaddr) != 0)
	{
		fprintf(stderr, "error: could not get IP address for %s: %s\n", o_int, strerror(errno));
		cleanup(1);
	}
	else
	{
		for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next)
		{
			if (ifa->ifa_addr == NULL)
				continue;

			if ((strcmp(ifa->ifa_name, o_int) == 0) && (ifa->ifa_addr->sa_family == AF_INET || (ifa->ifa_addr->sa_family == AF_INET6 && !o_skipIpV6)))
			{
				if (ifa->ifa_addr->sa_family == AF_INET)
					has_ipv4 = 1;
				if (ifa->ifa_addr->sa_family == AF_INET6)
					has_ipv6 = 1;
				if ((myip = calloc(1, sizeof(ip_literal_t))) == NULL)
				{
					perror("malloc");
					exit(1);
				}
				else if ((myip->value = calloc(1, NI_MAXHOST)) == NULL)
				{
					perror("malloc");
					exit(1);
				}
				else
				{
					size_t size = (ifa->ifa_addr->sa_family == AF_INET6) ? sizeof(struct sockaddr_in6) : sizeof(struct sockaddr_in);
					myip->is_ipv6 = (ifa->ifa_addr->sa_family == AF_INET6) ? 1 : 0;

					if (getnameinfo(ifa->ifa_addr, size, myip->value, NI_MAXHOST, NULL, 0, NI_NUMERICHOST) != 0)
					{
						fprintf(stderr, "error: could not get IP address for %s: %s\n", o_int, strerror(errno));
						freeifaddrs(ifaddr);
						cleanup(1);
					}
					else
					{
						char *ptr = strchr(myip->value, '%');
						if (ptr != NULL)
							*ptr = '\0';
						if (myips)
							myip->next = myips;
						myips = myip;
						dprint("local IP: %s\n", myip->value);
					}
				}
			}
		}
		freeifaddrs(ifaddr);
	}

	generate_pcap_filter();

	if (o_daemon)
	{
		FILE *pidfp;
		if (daemon(0, 0) < 0)
		{
			perror("daemon");
			cleanup(1);
		}
		/* write our PID to the pidfile*/
		if ((pidfp = fopen(o_pidfile, "w")))
		{
			fprintf(pidfp, "%d\n", getpid());
			fclose(pidfp);
		}
		else
		{
			dprint("could not create pid file %s: %s\n", o_pidfile, strerror(errno));
			logprint("could not create pid file %s: %s", o_pidfile, strerror(errno));
		}
	}

	signal(SIGINT, cleanup);
	signal(SIGTERM, cleanup);
	signal(SIGCHLD, child_exit);
	signal(SIGHUP, reload);

	vprint("listening on %s...\n", o_int);
	logprint("starting up, listening on %s", o_int);
	ret = 1;
	while (ret >= 0)
	{
		ret = pcap_dispatch(cap, -1, sniff, NULL);
	}
	dprint("bailed out of main loop! (ret=%d)\n", ret);
	pcap_perror(cap, "pcap");

	cleanup(0);
	/* notreached */
	exit(0);
}

void dprint(char *fmt, ...)
{
	va_list args;
	if (o_debug)
	{
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		fflush(stdout);
	}
}

void vprint(char *fmt, ...)
{
	va_list args;
	if (o_verbose)
	{
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		fflush(stdout);
	}
}

/* Output a message to syslog and/or a logfile */
void logprint(char *fmt, ...)
{
	char msg[1024];
	va_list args;
	va_start(args, fmt);
	vsnprintf(msg, 1024, fmt, args);
	va_end(args);
	if (o_usesyslog)
	{
		syslog(LOG_NOTICE, "%s", msg);
	}
	if (logfd)
	{
		time_t t;
		struct tm *tm;
		t = time(NULL);
		tm = localtime(&t);

		fprintf(logfd, "[%04d-%02d-%02d %02d:%02d] %s\n", tm->tm_year + 1900,
				tm->tm_mon + 1, tm->tm_mday, tm->tm_hour, tm->tm_min, msg);
		fflush(logfd);
	}
}

/* Output current sequence of door for debugging */
void dprint_sequence(opendoor_t *door, char *fmt, ...)
{
	va_list args;
	int i;

	if (o_debug)
	{
		va_start(args, fmt);
		vprintf(fmt, args);
		va_end(args);
		for (i = 0; i < door->seqcount; i++)
		{
			switch (door->protocol[i])
			{
			case IPPROTO_UDP:
				printf((i == door->seqcount - 1 ? "%u:udp\n" : "%u:udp,"), door->sequence[i]);
				break;
			case IPPROTO_TCP: /* fallthrough */
			default:
				printf((i == door->seqcount - 1 ? "%u:tcp\n" : "%u:tcp,"), door->sequence[i]);
			}
		}
		fflush(stdout);
	}
}

/* Signal handlers */
void cleanup(int signum)
{
	ip_literal_t *myip = myips, *next;
	int status;

	vprint("waiting for child processes...\n");
	wait(&status);

	vprint("closing...\n");
	logprint("shutting down");
	pcap_close(cap);
	if (o_daemon)
	{
		unlink(o_pidfile);
	}

	for (; myip; myip = next)
	{
		if (myip->value)
		{
			free(myip->value);
		}
		next = myip->next;
		free(myip);
	}

	exit(signum);
}

void child_exit(int signum)
{
	int status;
	while (waitpid((pid_t)-1, &status, WNOHANG) > 0)
		continue;
}

void reload(int signum)
{
	PMList *lp;
	opendoor_t *door;
	int res_cfg;

	vprint("re-reading config file: %s\n", o_cfg);
	logprint("re-reading config file: %s\n", o_cfg);

	for (lp = doors; lp; lp = lp->next)
	{
		door = (opendoor_t *)lp->data;
		free_door(door);
		lp->data = NULL;
	}
	list_free(doors);
	doors = NULL;

	list_free(credentials);

	list_free(attempts);
	attempts = NULL;

	res_cfg = parseconfig(o_cfg);

	vprint("closing log file: %s\n", o_logfile);

	/* close the log file */
	if (logfd)
	{
		fclose(logfd);
		logfd = NULL;
	}

	if (res_cfg)
	{
		exit(1);
	}

	vprint("re-opening log file: %s\n", o_logfile);
	logprint("re-opening log file: %s\n", o_logfile);

	/* re-open the log file */
	logfd = fopen(o_logfile, "a");
	if (logfd == NULL)
	{
		perror("warning: cannot open logfile");
	}

	/* Fix issue #2 by regenerating the PCAP filter post config file re-read */
	generate_pcap_filter();

	return;
}

void usage(int exit_code)
{
	printf("usage: knockd [options]\n");
	printf("options:\n");
	printf("  -i, --interface <int>  network interface to listen on (default \"eth0\")\n");
	printf("  -d, --daemon           run as a daemon\n");
	printf("  -c, --config <file>    use an alternate config file\n");
	printf("  -D, --debug            output debug messages\n");
	printf("  -l, --lookup           lookup DNS names (may be a security risk)\n");
	printf("  -p, --pidfile          use an alternate pidfile\n");
	printf("  -g, --logfile          use an alternate logfile\n");
	printf("  -v, --verbose          be verbose\n");
	printf("  -4, --only-ip-v4       do not track ipv6\n");
	printf("  -V, --version          display version\n");
	printf("  -h, --help             this help\n");
	printf("\n");
	exit(exit_code);
}

void ver()
{
	printf("knockd %s\n", version);
	printf("Developed by: \n");
	printf("Copyright (C) 2025 Alberto Novoa Gonzalez <angonzalez22@esei.uvigo.es>\n");
	printf("Based on version 0.8 code developed by:\n");
	printf("Copyright (C) 2004-2012 Judd Vinet <jvinet@zeroflux.org>\n");

	exit(0);
}

/* Convert a string to uppercase
 */
char *strtoupper(char *str)
{
	char *ptr = str;

	while (*ptr)
	{
		(*ptr) = toupper(*ptr);
		ptr++;
	}
	return str;
}

/* Trim whitespace and newlines from a string
 */
char *trim(char *str)
{
	char *pch = str;
	while (isspace(*pch))
	{
		pch++;
	}
	if (pch != str)
	{
		memmove(str, pch, (strlen(pch) + 1));
	}

	size_t len = strlen(str);
	if (len == 0)
	{
		return str;
	}

	pch = (char *)(str + (len - 1));
	while (isspace(*pch))
	{
		pch--;
	}
	*++pch = '\0';

	return str;
}

/* Parse a config file
 */
int parseconfig(char *configfile)
{
	FILE *fp = NULL;
	char line[PATH_MAX + 1];
	char *ptr = NULL;
	char *key = NULL;
	int linenum = 0;
	char section[256] = "";
	opendoor_t *door = NULL;
	PMList *lp;

	if ((fp = fopen(configfile, "r")) == NULL)
	{
		perror(configfile);
		return (1);
	}

	while (fgets(line, PATH_MAX, fp))
	{
		linenum++;
		trim(line);
		if (strlen(line) == 0 || line[0] == '#')
		{
			continue;
		}
		if (line[0] == '[' && line[strlen(line) - 1] == ']')
		{
			/* new config section */
			ptr = line;
			ptr++;
			strncpy(section, ptr, sizeof(section));
			section[sizeof(section) - 1] = '\0';
			section[strlen(section) - 1] = '\0';
			dprint("config: new section: '%s'\n", section);
			if (!strlen(section))
			{
				fprintf(stderr, "config: line %d: bad section name\n", linenum);
				return (1);
			}
			if (strcmp(section, "options"))
			{
				/* start a new knock/event record */
				door = malloc(sizeof(opendoor_t));
				if (door == NULL)
				{
					perror("malloc");
					exit(1);
				}
				strncpy(door->name, section, sizeof(door->name) - 1);
				door->name[sizeof(door->name) - 1] = '\0';
				door->target = 0;
				door->seqcount = 0;
				door->seq_timeout = SEQ_TIMEOUT; /* default sequence timeout (seconds)  */
				door->start_command = NULL;
				door->start_command6 = NULL;
				door->cmd_timeout = CMD_TIMEOUT; /* default command timeout (seconds) */
				door->stop_command = NULL;
				door->stop_command6 = NULL;
				door->flag_fin = DONT_CARE;
				door->flag_syn = DONT_CARE;
				door->flag_rst = DONT_CARE;
				door->flag_psh = DONT_CARE;
				door->flag_ack = DONT_CARE;
				door->flag_urg = DONT_CARE;
				door->one_time_sequences_fd = NULL;
				door->pcap_filter_exp = NULL;
				door->pcap_filter_expv6 = NULL;
				doors = list_add(doors, door);
			}
		}
		else
		{
			/* directive */
			if (!strlen(section))
			{
				fprintf(stderr, "config: line %d: all directives must belong to a section\n", linenum);
				return (1);
			}
			ptr = line;
			key = strsep(&ptr, "=");
			if (key == NULL)
			{
				fprintf(stderr, "config: line %d: syntax error\n", linenum);
				return (1);
			}
			trim(key);
			key = strtoupper(key);
			if (ptr == NULL)
			{
				if (!strcmp(key, "USESYSLOG"))
				{
					o_usesyslog = 1;
					dprint("config: usesyslog\n");
				}
				else
				{
					fprintf(stderr, "config: line %d: syntax error\n", linenum);
					return (1);
				}
			}
			else
			{
				trim(ptr);
				if (!strcmp(section, "options"))
				{
					if (!strcmp(key, "LOGFILE"))
					{
						strncpy(o_logfile, ptr, PATH_MAX - 1);
						o_logfile[PATH_MAX - 1] = '\0';
						dprint("config: log file: %s\n", o_logfile);
					}
					else if (!strcmp(key, "PIDFILE"))
					{
						strncpy(o_pidfile, ptr, PATH_MAX - 1);
						o_pidfile[PATH_MAX - 1] = '\0';
						dprint("config: pid file: %s\n", o_pidfile);
					}
					else if (!strcmp(key, "INTERFACE"))
					{
						/* set interface only if it has not already been set by the -i switch */
						if (strlen(o_int) == 0)
						{
							strncpy(o_int, ptr, sizeof(o_int) - 1);
							o_int[sizeof(o_int) - 1] = '\0';
							dprint("config: interface: %s\n", o_int);
						}
					}
					else
					{
						fprintf(stderr, "config: line %d: syntax error\n", linenum);
						return (1);
					}
				}
				else
				{
					if (door == NULL)
					{
						fprintf(stderr, "config: line %d: \"%s\" can only be used within a Door section\n",
								linenum, key);
						return (1);
					}
					if (!strcmp(key, "TARGET"))
					{
						door->target = malloc(sizeof(char) * (strlen(ptr) + 1));
						if (door->target == NULL)
						{
							perror("malloc");
							exit(1);
						}
						strcpy(door->target, ptr);
						dprint("config: %s: target: %s\n", door->name, door->target);
					}
					else if (!strcmp(key, "SEQUENCE"))
					{
						int i;
						i = parse_port_sequence(ptr, door);
						if (i > 0)
						{
							return (i);
						}
						dprint_sequence(door, "config: %s: sequence: ", door->name);
					}
					else if (!strcmp(key, "ONE_TIME_SEQUENCES"))
					{
						if ((door->one_time_sequences_fd = fopen(ptr, "r+")) == NULL)
						{
							perror(ptr);
							return (1);
						}
					}
					else if (!strcmp(key, "SEQ_TIMEOUT") || !strcmp(key, "TIMEOUT"))
					{
						door->seq_timeout = (time_t)atoi(ptr);
						dprint("config: %s: seq_timeout: %d\n", door->name, door->seq_timeout);
					}
					else if (!strcmp(key, "START_COMMAND") || !strcmp(key, "COMMAND"))
					{
						door->start_command = malloc(sizeof(char) * (strlen(ptr) + 1));
						if (door->start_command == NULL)
						{
							perror("malloc");
							exit(1);
						}
						strcpy(door->start_command, ptr);
						dprint("config: %s: start_command: %s\n", door->name, door->start_command);
					}
					else if (!strcmp(key, "START_COMMAND_6") || !strcmp(key, "COMMAND_6"))
					{
						door->start_command6 = malloc(sizeof(char) * (strlen(ptr) + 1));
						if (door->start_command6 == NULL)
						{
							perror("malloc");
							exit(1);
						}
						strcpy(door->start_command6, ptr);
						dprint("config: %s: start_command_6: %s\n", door->name, door->start_command6);
					}
					else if (!strcmp(key, "CMD_TIMEOUT"))
					{
						door->cmd_timeout = (time_t)atoi(ptr);
						dprint("config: %s: cmd_timeout: %d\n", door->name, door->cmd_timeout);
					}
					else if (!strcmp(key, "STOP_COMMAND"))
					{
						door->stop_command = malloc(sizeof(char) * (strlen(ptr) + 1));
						if (door->stop_command == NULL)
						{
							perror("malloc");
							exit(1);
						}
						strcpy(door->stop_command, ptr);
						dprint("config: %s: stop_command: %s\n", door->name, door->stop_command);
					}
					else if (!strcmp(key, "STOP_COMMAND_6"))
					{
						door->stop_command6 = malloc(sizeof(char) * (strlen(ptr) + 1));
						if (door->stop_command6 == NULL)
						{
							perror("malloc");
							exit(1);
						}
						strcpy(door->stop_command6, ptr);
						dprint("config: %s: stop_command_6: %s\n", door->name, door->stop_command6);
					}
					else if (!strcmp(key, "TCPFLAGS"))
					{
						char *flag;
						strtoupper(ptr);
						while ((flag = strsep(&ptr, ",")))
						{
							/* allow just some flags to be specified */
							if (!strcmp(flag, "FIN"))
							{
								door->flag_fin = SET;
							}
							else if (!strcmp(flag, "!FIN"))
							{
								door->flag_fin = NOT_SET;
							}
							else if (!strcmp(flag, "SYN"))
							{
								door->flag_syn = SET;
							}
							else if (!strcmp(flag, "!SYN"))
							{
								door->flag_syn = NOT_SET;
							}
							else if (!strcmp(flag, "RST"))
							{
								door->flag_rst = SET;
							}
							else if (!strcmp(flag, "!RST"))
							{
								door->flag_rst = NOT_SET;
							}
							else if (!strcmp(flag, "PSH"))
							{
								door->flag_psh = SET;
							}
							else if (!strcmp(flag, "!PSH"))
							{
								door->flag_psh = NOT_SET;
							}
							else if (!strcmp(flag, "ACK"))
							{
								door->flag_ack = SET;
							}
							else if (!strcmp(flag, "!ACK"))
							{
								door->flag_ack = NOT_SET;
							}
							else if (!strcmp(flag, "URG"))
							{
								door->flag_urg = SET;
							}
							else if (!strcmp(flag, "!URG"))
							{
								door->flag_urg = NOT_SET;
							}
							else
							{
								fprintf(stderr, "config: line %d: unrecognized flag \"%s\"\n",
										linenum, flag);
								return (1);
							}
							dprint("config: tcp flag: %s\n", flag);
						}
					}
					else
					{
						fprintf(stderr, "config: line %d: syntax error\n", linenum);
						return (1);
					}
				}
				line[0] = '\0';
			}
		}
	}
	fclose(fp);

	/* sanity checks */
	for (lp = doors; lp; lp = lp->next)
	{
		door = (opendoor_t *)lp->data;
		if (door->seqcount == 0)
		{
			fprintf(stderr, "error: section '%s' has an empty knock sequence\n", door->name);
			return (1);
		}
	}

	return (0);
}

/* Parse a port:protocol sequence. Returns a positive integer on error.
 */
int parse_port_sequence(char *sequence, opendoor_t *door)
{
	char *num;
	char *protocol;
	char *port;
	int portnum;

	door->seqcount = 0; /* reset seqcount */
	while ((num = strsep(&sequence, ",")))
	{
		if (door->seqcount >= SEQ_MAX)
		{
			fprintf(stderr, "config: section %s: too many ports in knock sequence\n", door->name);
			logprint("error: section %s: too many ports in knock sequence\n", door->name);
			return (1);
		}
		port = strsep(&num, ":");
		/* convert to 4-byte int first so we can easily detect a short overflow */
		portnum = atoi(port);
		if (portnum > 65535)
		{
			fprintf(stderr, "config: section %s: port %s is invalid\n", door->name, port);
			return (1);
		}
		door->sequence[door->seqcount++] = (unsigned short)portnum;
		if ((protocol = strsep(&num, ":")))
		{
			protocol = strtoupper(trim(protocol));
			if (!strcmp(protocol, "TCP"))
			{
				door->protocol[door->seqcount - 1] = IPPROTO_TCP;
			}
			else if (!strcmp(protocol, "UDP"))
			{
				door->protocol[door->seqcount - 1] = IPPROTO_UDP;
			}
			else
			{
				fprintf(stderr, "config: section %s: unknown protocol in knock sequence\n", door->name);
				logprint("error: section %s: unknown protocol in knock sequence\n", door->name);
				return (1);
			}
		}
		else
		{
			door->protocol[door->seqcount - 1] = IPPROTO_TCP; /* default protocol */
		}
	}
	return (0);
}




/* Generate and set the filter for pcap. That way only the relevant packets will
 * be forwarded to us (in sniff()). Note that generate_pcap_filter() will first
 * generate a subfilter (=substring of the whole filter string) for each door if
 * door->pcap_filter_exp is NULL. This behaviour can be used for doors with one
 * time sequences, where the subfilter has to be generated after each sequence.
 */
void generate_pcap_filter()
{
	PMList *lp;
	opendoor_t *door;
	credential_t *cred;
	ip_literal_t *myip;
	char *buffer = NULL;   /* temporary buffer to create the individual filter strings */
	size_t bufsize = 0;	   /* size of buffer */
	char port_str[10];	   /* used by snprintf to convert unsigned short --> string */
	short head_set = 0;	   /* flag indicating if protocol head is set (i.e. "((tcp dst port") */
	short tcp_present = 0; /* flag indicating if TCP is used */
	short udp_present = 0; /* flag indicating if UDP is used */
	unsigned int i;
	short modified_filters = 0;	 /* flag indicating if at least one filter has changed --> recompile the filter */
	struct bpf_program bpf_prog; /* compiled BPF filter program */
	int ipv6;

	/* generate subfilters for each door having a NULL pcap_filter_exp
	 *
	 * Example filter for one single door:
	 * ((tcp dst port 8000 or 8001 or 8002) and tcp[tcpflags] & tcp-syn != 0) or (udp dst port 4000 or 4001)
	 */
	for (ipv6 = 0; ipv6 <= 1; ipv6++)
	{
		if (ipv6 == 0 && !has_ipv4)
			continue;
		if (ipv6 == 1 && !has_ipv6)
			continue;

		if (ipv6 && o_skipIpV6)
			continue;

		for (lp = credentials; lp; lp = lp->next)
		{
			cred = (credential_t *)lp->data;

			/* if we get here at least one door had a pcap_filter_exp == NULL */
			modified_filters = 1;

			head_set = 0;
			tcp_present = 0;
			udp_present = 0;

			/* allocate memory for buffer if needed.
			 * The first allocation will be 200 Bytes (should be large enough for common sequences). If there is
			 * not enough space, a call to realloc_strcat() will eventually increase its size. The buffer will be
			 * reused for successive doors */
			if (buffer == NULL)
			{
				bufsize = 200;
				buffer = (char *)malloc(sizeof(char) * bufsize);
				if (buffer == NULL)
				{
					perror("malloc");
					cleanup(1);
				}
				buffer[0] = '\0';
			}

			/* accept only incoming packets */
			for (myip = myips; myip != NULL; myip = myip->next)
			{
				if (myip->is_ipv6 != ipv6)
					continue;
				if (!head_set)
				{
					bufsize = realloc_strcat(&buffer, "((dst host ", bufsize);
					head_set = 1;
				}
				else
				{
					bufsize = realloc_strcat(&buffer, " or dst host ", bufsize);
				}
				bufsize = realloc_strcat(&buffer, myip->value, bufsize);
			}

			bufsize = realloc_strcat(&buffer, ") and (", bufsize);
			head_set = 0;

			/* generate filter for all TCP ports (i.e. "((tcp dst port 4000 or 4001 or 4002) and tcp[tcpflags] & tcp-syn != 0)" */
			for (i = 0; i < cred->keySequenceCount; i++)
			{
				// if(door->protocol[i] == IPPROTO_TCP) {
				if (!head_set)
				{ /* first TCP port in the sequence */
					bufsize = realloc_strcat(&buffer, "((tcp dst port ", bufsize);
					head_set = 1;
					tcp_present = 1;
				}
				else
				{ /* not the first TCP port in the sequence */
					bufsize = realloc_strcat(&buffer, " or ", bufsize);
				}
				snprintf(port_str, sizeof(port_str), "%hu", cred->keySequence[i]); /* unsigned short to string */
				bufsize = realloc_strcat(&buffer, port_str, bufsize);			   /* append port number */
																				   //}
			}
			if (tcp_present)
			{
				bufsize = realloc_strcat(&buffer, ")", bufsize); /* close parentheses of TCP ports */
			}

			/* append the TCP flag filters */
			if (tcp_present)
			{
				bufsize = realloc_strcat(&buffer, ")", bufsize); /* close parentheses of flags */
			}


			bufsize = realloc_strcat(&buffer, "))", bufsize); /* close parantheses around port filters */

			/* test if in any of the precedent calls to realloc_strcat() failed. We can do this safely here because
			 * realloc_strcat() returns 0 on failure and if a buffer size of 0 is passed to it, the function does
			 * nothing but returning 0 again. Because we never read buffer in the above code, it is secure to test
			 * for failure only at this point (it makes the code more readable than checking for failure each time
			 * realloc_strcat() is called). */
			if (bufsize == 0)
			{
				perror("realloc");
				cleanup(1);
			}

			/* allocate the buffer in door holding the filter string, copy it and prepare buffer for being reused. */
			if (ipv6)
			{
				cred->pcap_filter_expv6 = (char *)malloc(strlen(buffer) + 1);
				if (cred->pcap_filter_expv6 == NULL)
				{
					perror("malloc");
					cleanup(1);
				}
				strcpy(cred->pcap_filter_expv6, buffer);
				dprint("adding pcap expression for door '%s': %s\n", "default", cred->pcap_filter_expv6);
			}
			else
			{
				cred->pcap_filter_exp = (char *)malloc(strlen(buffer) + 1);
				if (cred->pcap_filter_exp == NULL)
				{
					perror("malloc");
					cleanup(1);
				}
				strcpy(cred->pcap_filter_exp, buffer);
				dprint("adding pcap expression for door '%s': %s\n", "default", cred->pcap_filter_exp);
			}
			buffer[0] = '\0'; /* "clear" the buffer */
		}
	}

	/* generate the whole pcap filter string if a filter had been modified. Reuse
	 * buffer (already "cleared").
	 *
	 * Note that we don't check if a port is included in multiple doors, we
	 * simply concatenate the individual door filters and rely on pcap's
	 * optimization capabilities.
	 *
	 * Example filter for two doors with these sequences:
	 *   (1) 8000:tcp,4000:udp,8001:tcp,4001:udp,8002:tcp (syn); and
	 *   (2) 1234:tcp,4567:tcp,8901:tcp (syn,ack)
	 *
	 * Filter:
	 *   dst host the.hosts.ip.address and
	 *   (
	 *     ((tcp dst port 8000 or 8001 or 8002)
	 *       and tcp[tcpflags] & tcp-syn != 0)
	 *     or (udp dst port 4000 or 4001)
	 *     or ((tcp dst port 1234 or 4567 or 8901)
	 *         and tcp[tcpflags] & tcp-syn != 0
	 *         and tcp[tcpflags] & tcp-ack != 0)
	 *   )
	 */
	if (modified_filters)
	{
		/* iterate over all doors */
		int first = 1;
		for (lp = credentials; lp; lp = lp->next)
		{
			cred = (credential_t *)lp->data;
			for (ipv6 = 0; ipv6 <= 1; ipv6++)
			{
				if (ipv6 == 0 && !has_ipv4)
					continue;
				if (ipv6 == 1 && !has_ipv6)
					continue;

				if (ipv6 && o_skipIpV6)
					continue;

				if (first)
					first = 0;
				else
					bufsize = realloc_strcat(&buffer, " or ", bufsize);
				if (ipv6)
					bufsize = realloc_strcat(&buffer, cred->pcap_filter_expv6, bufsize);
				else
					bufsize = realloc_strcat(&buffer, cred->pcap_filter_exp, bufsize);
			}
		}

		/* test if in any of the precedent calls to realloc_strcat() failed. See above why this is ok to do this only
		 * at this point */
		if (bufsize == 0)
		{
			perror("realloc");
			cleanup(1);
		}

		vprint("adding pcap expression for all doors: %s\n", buffer);
		if (pcap_compile(cap, &bpf_prog, buffer, 1, 0) < 0)
		{ /* optimize filter (1), no netmask (0) (we're not interested in broadcasts) */
			pcap_perror(cap, "pcap_compile");
			cleanup(1);
		}
		if (pcap_setfilter(cap, &bpf_prog) < 0)
		{
			pcap_perror(cap, "pcap_setfilter");
			cleanup(1);
		}
		pcap_freecode(&bpf_prog);
		free(buffer);
	}
}

/* Reallocating strcat -- appends the src string to the dest string (pointer to
 * char*!) overwriting the `\0' character at the end of dest, and then adds a
 * terminating `\0' character. size is the whole size of the dest buffer (not
 * the remaining space like in strncat). If there is not enough space to append
 * src, the dest buffer will be realloc()ated to hold the src string. The
 * reallocation is done by doubling dest's size until it is large enough. dest
 * will always be NULL terminated. Returns the size of the whole buffer or 0 if
 * realloc() fails.
 *
 * IMPORTANT: dest has to be an allocated buffer (not static!), such that it can
 * be reallocated with realloc() !!!
 */
size_t realloc_strcat(char **dest, const char *src, size_t size)
{
	size_t needed_size;
	size_t new_size;
	char *orig = *dest;

	if (size == 0)
	{
		free(orig);
		return 0;
	}

	needed_size = strlen(*dest) + strlen(src) + 1; /* '+ 1' for '\0' */
	new_size = size;

	while (needed_size > new_size)
	{
		new_size *= 2;
	}
	if (new_size != size)
	{
		*dest = (char *)realloc(*dest, new_size);
		if (*dest == NULL)
		{
			free(orig);
			return 0;
		}
	}

	/* now dest is large enough to strcat() the src */
	strcat(*dest, src);

	return new_size;
}

void free_door(opendoor_t *door)
{
	if (door)
	{
		free(door->target);
		free(door->start_command);
		free(door->stop_command);
		if (door->one_time_sequences_fd)
		{
			fclose(door->one_time_sequences_fd);
		}
		free(door->pcap_filter_exp);
		free(door);
	}
}

/* Disable the door by removing it from the doors list and free all allocated memory.
 */
void close_door(opendoor_t *door)
{
	doors = list_remove(doors, door);
	free_door(door);
}

void unvalidate_credentials(credential_t *cred)
{
	credentials = list_remove(credentials, cred);
}

/* Get the IP address of an interface
 */
char *get_ip(const char *iface, char *buf, int bufsize)
{
	int s;
	struct ifreq ifr;

	if (bufsize <= 0)
	{
		return (NULL);
	}
	if (buf == NULL)
	{
		return (NULL);
	}
	buf[0] = '\0';

	s = socket(AF_INET, SOCK_DGRAM, 0);
	if (s < 0)
	{
		return (NULL);
	}

	bzero((void *)(&ifr.ifr_name), sizeof(ifr.ifr_name));
	strncpy(ifr.ifr_name, iface, sizeof(ifr.ifr_name) - 1);
	ifr.ifr_name[sizeof(ifr.ifr_name) - 1] = '\0';
	if (ioctl(s, SIOCGIFADDR, &ifr))
	{
		close(s);
		return (NULL);
	}
	close(s);

	strncpy(buf, inet_ntoa((*(struct sockaddr_in *)&ifr.ifr_addr).sin_addr), bufsize - 1);
	buf[bufsize - 1] = '\0';
	return (buf);
}

/* Parse a command line, replacing tokens (eg, %IP%) with their real values and
 * copy the result to dest. At most size-1 characters will be copied and the
 * result will always be NULL terminated (except if size == 0). The return value
 * is the length of the resulting string. If the returned size is larger than the
 * size of dest, then the result has ben truncated.
 */
size_t parse_cmd(char *dest, size_t size, const char *command, const char *src)
{
	char *d = dest;
	const char *c = command;
	const char *s = src;
	char *token;
	size_t n = size;
	size_t command_len = strlen(command);
	size_t total_len = 0;

	/* allows us to calculate total length of result string even if the size */
	/* is zero by setting n to 1 (--> noting will be ever written to dest) */
	int size_larger_than_zero = 1;
	if (size == 0)
	{
		size_larger_than_zero = 0;
		n = 1;
	}

	/* get location of first token */
	token = strstr(c, "%IP%");
	if (!token)
	{
		/* point token past command (we won't access it anymore) */
		token = (char *)(c + command_len + 1);
	}
	while (*c != '\0')
	{
		/* not reached a token yet --> append from command */
		if (c < token)
		{
			if (n != 1)
			{
				*d++ = *c;
				n--;
			}
		}
		else
		{
			/* we reached a token --> append from src */
			while (*s != '\0')
			{
				if (n != 1)
				{
					*d++ = *s;
					n--;
				}
				s++;
				total_len++;
			}
			c += 4;					   /* skip the token in command */
			s = src;				   /* "rewind" src string for next token */
			token = strstr(c, "%IP%"); /* get location of next token */
			if (!token)
			{
				/* point token past command (we won't access it anymore) */
				token = (char *)(c + command_len + 1);
			}
			c--;		 /* compensate for the following c++ */
			total_len--; /* compensate for the following total_len++ */
		}
		c++;
		total_len++;
	}
	if (size_larger_than_zero)
	{
		/* terminate dest if its size is larger than 0 */
		*d = '\0';
	}

	return (total_len);
}

/* Execute a command through the system shell and wait for return
 */
int exec_cmd(char *command, char *name)
{
	int ret;

	logprint("%s: running command: %s\n", name, command);
	vprint("%s: running command: %s\n", name, command);
	ret = system(command);
	if (ret == -1)
	{
		fprintf(stderr, "error: command fork failed!\n");
		logprint("error: command fork failed!");
	}
	else if (ret != 0)
	{
		fprintf(stderr, "%s: command returned non-zero status code (%d)\n", name, WEXITSTATUS(ret));
		logprint("%s: command returned non-zero status code (%d)", name, WEXITSTATUS(ret));
	}
	return ret;
}

int open_mqtt_port(knocker_t sealer)
{
	int ret;
	if (sealer.cred->MQTT_port == 0)
	{
		vprint("no mqtt port configured, skipping...\n");
		return 0;
	}
	// Open the MQTT port
	char command[100];
	snprintf(command, sizeof(command), "iptables -A INPUT -p tcp --dport %d -j ACCEPT", 8883);
	ret = system(command);
	snprintf(command, sizeof(command), "iptables -A INPUT -i lo -j ACCEPT");
	ret = ret | system(command);
	if(sealer.from_ipv6)
	{
		snprintf(command, sizeof(command), "ip6tables -A INPUT -p tcp --dport %d -j ACCEPT", 8883);
		ret = ret | system(command);
		snprintf(command, sizeof(command), "ip6tables -A INPUT -i lo -j ACCEPT");
		ret = ret | system(command);
		vprint("opened mqtt port for ipv6\n");
	}
	if (ret != 0)
	{
		vprint("failed to open mqtt port, skipping...\n");
		return 1;
	}
	return 0;
}

int open_mqtt_port_fwd(knocker_t sealer)
{
	int ret;
	if (sealer.cred->MQTT_port == 0)
	{
		vprint("no mqtt port configured for door %s, skipping...\n", sealer.door->name);
		return 0;
	}
	// Open the MQTT port
	char command[100];
	snprintf(command, sizeof(command), "iptables -t nat -A PREROUTING -p tcp --dport %d -j REDIRECT --to-port 1883", sealer.cred->MQTT_port);
	ret = system(command);

	return 0;
}

int close_mqtt_port(knocker_t sealer)
{
	int ret;
	if (sealer.cred->MQTT_port == 0)
	{
		vprint("no mqtt port configured, skipping...\n");
		return 0;
	}
	// Close the MQTT port
	char command[100];
	snprintf(command, sizeof(command), "iptables -D INPUT -p tcp --dport %d -j ACCEPT", 8883);
	ret = system(command);
	snprintf(command, sizeof(command), "iptables -D INPUT -i lo -j ACCEPT");
	ret = ret | system(command);
	if(sealer.from_ipv6)
	{
		snprintf(command, sizeof(command), "ip6tables -D INPUT -p tcp --dport %d -j ACCEPT", 8883);
		ret = ret | system(command);
		snprintf(command, sizeof(command), "ip6tables -D INPUT -i lo -j ACCEPT");
		ret = ret | system(command);
		vprint("closed mqtt port for ipv6\n");
	}
	if (ret != 0)
	{
		vprint("failed to close mqtt port, skipping...\n");
		return 1;
	}
	return 0;
}

int close_mqtt_port_fwd(knocker_t sealer)
{
	int ret;
	if (sealer.cred->MQTT_port == 0)
	{
		vprint("no mqtt port configured for door %s, skipping...\n", sealer.door->name);
		return 0;
	}
	// Close the MQTT port
	char command[100];
	snprintf(command, sizeof(command), "iptables -t nat -D OUTPUT -p tcp --dport %d -j REDIRECT --to-port 1883", sealer.cred->MQTT_port);
	ret = system(command);
	snprintf(command, sizeof(command), "iptables -t nat -D PREROUTING -p tcp --dport %d -j REDIRECT --to-port 1883", sealer.cred->MQTT_port);
	ret = system(command);
	snprintf(command, sizeof(command), "iptables -t nat -D OUTPUT -p tcp --sport 1883 -j REDIRECT --to-port %d", sealer.cred->MQTT_port);
	ret = system(command);
	snprintf(command, sizeof(command), "iptables -t nat -D PREROUTING -p tcp --sport 1883 -j REDIRECT --to-port %d", sealer.cred->MQTT_port);
	ret = system(command);
	if (ret != 0)
	{
		vprint("failed to close mqtt port for door %s, skipping...\n", sealer.door->name);
		return 1;
	}
	return 0;
}

/*
 * If examining a TCP packet, try to match flags against those in
 * the door config.
 */
int flags_match(opendoor_t *door, int ip_proto, struct tcphdr *tcp)
{
	/* if tcp, check the flags to ignore the packets we don't want
	 * (don't even use it to cancel sequences)
	 */
	if (ip_proto == IPPROTO_TCP)
	{
		if (door->flag_fin != DONT_CARE)
		{
			if (door->flag_fin == SET && !(tcp->th_flags & TH_FIN))
			{
				dprint("packet is not FIN, ignoring...\n");
				return 0;
			}
			if (door->flag_fin == NOT_SET && (tcp->th_flags & TH_FIN))
			{
				dprint("packet is not !FIN, ignoring...\n");
				return 0;
			}
		}
		if (door->flag_syn != DONT_CARE)
		{
			if (door->flag_syn == SET && !(tcp->th_flags & TH_SYN))
			{
				dprint("packet is not SYN, ignoring...\n");
				return 0;
			}
			if (door->flag_syn == NOT_SET && (tcp->th_flags & TH_SYN))
			{
				dprint("packet is not !SYN, ignoring...\n");
				return 0;
			}
		}
		if (door->flag_rst != DONT_CARE)
		{
			if (door->flag_rst == SET && !(tcp->th_flags & TH_RST))
			{
				dprint("packet is not RST, ignoring...\n");
				return 0;
			}
			if (door->flag_rst == NOT_SET && (tcp->th_flags & TH_RST))
			{
				dprint("packet is not !RST, ignoring...\n");
				return 0;
			}
		}
		if (door->flag_psh != DONT_CARE)
		{
			if (door->flag_psh == SET && !(tcp->th_flags & TH_PUSH))
			{
				dprint("packet is not PSH, ignoring...\n");
				return 0;
			}
			if (door->flag_psh == NOT_SET && (tcp->th_flags & TH_PUSH))
			{
				dprint("packet is not !PSH, ignoring...\n");
				return 0;
			}
		}
		if (door->flag_ack != DONT_CARE)
		{
			if (door->flag_ack == SET && !(tcp->th_flags & TH_ACK))
			{
				dprint("packet is not ACK, ignoring...\n");
				return 0;
			}
			if (door->flag_ack == NOT_SET && (tcp->th_flags & TH_ACK))
			{
				dprint("packet is not !ACK, ignoring...\n");
				return 0;
			}
		}
		if (door->flag_urg != DONT_CARE)
		{
			if (door->flag_urg == SET && !(tcp->th_flags & TH_URG))
			{
				dprint("packet is not URG, ignoring...\n");
				return 0;
			}
			if (door->flag_urg == NOT_SET && (tcp->th_flags & TH_URG))
			{
				dprint("packet is not !URG, ignoring...\n");
				return 0;
			}
		}
	}
	return 1;
}

/**
 * Process a knock attempt to see if the knocker has graduated to the next
 * sequence. If they've completed all sequences correctly, then we open the
 * door.
 */


void process_attempt(knocker_t *attempt)
{

	/* level up! */
	attempt->stage++;

	if (attempt->srchost)
	{
		vprint("%s (%s): Stage %d\n", attempt->src, attempt->srchost, attempt->stage);
		logprint("%s (%s): Stage %d", attempt->src, attempt->srchost,  attempt->stage);
	}
	else
	{
		vprint("%s: Stage %d\n", attempt->src,  attempt->stage);
		logprint("%s: Stage %d", attempt->src, attempt->stage);
	}
	int pid;
	if (attempt->stage >= attempt->cred->keySequenceCount)
	{
		if (attempt->srchost)
		{
			vprint("%s (%s): OPEN SESAME\n", attempt->src, attempt->srchost);
			logprint("%s (%s): OPEN SESAME", attempt->src, attempt->srchost);
		}
		else
		{
			vprint("%s: OPEN SESAME\n", attempt->src);
			logprint("%s: OPEN SESAME", attempt->src);
		}

		/* run the associated command */

		/* child */
		secondPhaseManager(attempt);
		vprint("Iteration completed!\n");
	}
}

/* Sniff an interface, looking for port-knock sequences
 */
void sniff(u_char *arg, const struct pcap_pkthdr *hdr, const u_char *packet)
{
	/* packet structs */
	struct ether_header *eth = NULL;
	struct ip *ip = NULL;
	struct ip6_hdr *ip6 = NULL;
	struct tcphdr *tcp = NULL;
	struct udphdr *udp = NULL;
	char proto[8];
	/* TCP/IP data */
	struct in_addr inaddr;
	unsigned short sport = 0;
	unsigned short dport = 0;
	char src_ip[64], dst_ip[64];
	/* timestamp */
	time_t pkt_secs = hdr->ts.tv_sec;
	struct tm *pkt_tm;
	char pkt_date[11];
	char pkt_time[9];
	PMList *lp;
	knocker_t *attempt = NULL;
	PMList *found_attempts = NULL, *found_attempt;
	int ip_proto = 0;
	int from_ipv6 = 0;

	if (lltype == DLT_EN10MB)
	{
		eth = (struct ether_header *)packet;
		if (ntohs(eth->ether_type) != ETHERTYPE_IP && ntohs(eth->ether_type) != ETHERTYPE_IPV6)
		{
			return;
		}

		ip = (struct ip *)(packet + sizeof(struct ether_header));
		ip6 = (struct ip6_hdr *)(packet + sizeof(struct ether_header));
#ifdef __linux__
	}
	else if (lltype == DLT_LINUX_SLL)
	{
		ip = (struct ip *)((u_char *)packet + 16);
#endif
	}
	else if (lltype == DLT_RAW)
	{
		ip = (struct ip *)((u_char *)packet);
	}
	else
	{
		dprint("link layer header type of packet not recognized, ignoring...\n");
		return;
	}

	if (ip->ip_v != 4 && ip->ip_v != 6)
	{
		/* no IPv6 yet */
		dprint("packet is not IPv4 or IPv6, ignoring...\n");
		return;
	}

	if (ip->ip_v == 4)
	{
		if (ip->ip_p == IPPROTO_ICMP)
		{
			/* we don't do ICMP */
			return;
		}

		sport = dport = 0;
		from_ipv6 = 0;
		ip_proto = ip->ip_p;

		if (ip->ip_p == IPPROTO_TCP)
		{
			strncpy(proto, "tcp", sizeof(proto));
			tcp = (struct tcphdr *)((u_char *)ip + (ip->ip_hl * 4));
			sport = ntohs(tcp->th_sport);
			dport = ntohs(tcp->th_dport);
		}
		if (ip->ip_p == IPPROTO_UDP)
		{
			strncpy(proto, "udp", sizeof(proto));
			udp = (struct udphdr *)((u_char *)ip + (ip->ip_hl * 4));
			sport = ntohs(udp->uh_sport);
			dport = ntohs(udp->uh_dport);
		}
	}
	else if (ip->ip_v == 6)
	{
		if (ip6 == NULL)
		{
			fprintf(stderr, "IPv6 is not supported under this link-layer type\n");
			return;
		}
		/* we accept only TCP/UDP */
		if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_TCP && ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt != IPPROTO_UDP)
		{
			/* we don't do ICMP */
			dprint("Unsupported IPv6 protocol\n");
			return;
		}

		ip_proto = ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt;
		from_ipv6 = 1;
		sport = dport = 0;

		if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_TCP)
		{
			strncpy(proto, "tcp", sizeof(proto));
			tcp = (struct tcphdr *)(ip6 + 1);
			sport = ntohs(tcp->th_sport);
			dport = ntohs(tcp->th_dport);
		}
		if (ip6->ip6_ctlun.ip6_un1.ip6_un1_nxt == IPPROTO_UDP)
		{
			strncpy(proto, "udp", sizeof(proto));
			udp = (struct udphdr *)(ip6 + 1);
			sport = ntohs(udp->uh_sport);
			dport = ntohs(udp->uh_dport);
		}
	}

	/* get the date/time */
	pkt_tm = localtime(&pkt_secs);
	snprintf(pkt_date, 11, "%04d-%02d-%02d", pkt_tm->tm_year + 1900, pkt_tm->tm_mon,
			 pkt_tm->tm_mday);
	snprintf(pkt_time, 9, "%02d:%02d:%02d", pkt_tm->tm_hour, pkt_tm->tm_min,
			 pkt_tm->tm_sec);

	/* convert IPs from binary to string */
	if (ip->ip_v == 4)
	{
		inaddr.s_addr = ip->ip_src.s_addr;
		strncpy(src_ip, inet_ntoa(inaddr), sizeof(src_ip) - 1);
		src_ip[sizeof(src_ip) - 1] = '\0';
		inaddr.s_addr = ip->ip_dst.s_addr;
		strncpy(dst_ip, inet_ntoa(inaddr), sizeof(dst_ip) - 1);
		dst_ip[sizeof(dst_ip) - 1] = '\0';
	}
	else if (ip->ip_v == 6)
	{
		inet_ntop(AF_INET6, &ip6->ip6_src, src_ip, sizeof(src_ip));
		inet_ntop(AF_INET6, &ip6->ip6_dst, dst_ip, sizeof(src_ip));
	}
	else
	{
		// dprint("Invalid protocol (not ipv4 or ipv6) !");
		return;
	}

	dprint("%s %s: %s: %s:%d -> %s:%d %d bytes\n", pkt_date, pkt_time,
		   proto, src_ip, sport, dst_ip, dport, hdr->len);
	vprint("%s %s: %s: %s:%d -> %s:%d %d bytes\n", pkt_date, pkt_time,
		   proto, src_ip, sport, dst_ip, dport, hdr->len);

	/* clean up expired/completed/failed attempts */
	lp = attempts;
	while (lp != NULL)
	{
		int nix = 0; /* Clear flag */
		PMList *lpnext = lp->next;

		attempt = (knocker_t *)lp->data;


		/* Check if the sequence has been completed */
		if (attempt->stage >= attempt->cred->keySequenceCount)
		{
			dprint("removing successful knock attempt (%s)\n", attempt->src);
			nix = 1;
			vprint("removing successful knock attempt (%s)\n", attempt->src);
		}

		/* Signed integer overflow check.
		   If we received more than 32767 packets the sign will be negative*/
		if (attempt->stage < 0)
		{
			dprint("removing failed knock attempt (%s)\n", attempt->src);
			nix = 1;
			vprint("removing failed knock attempt (%s)\n", attempt->src);
		}

		

		// Check if timeout has been reached
		 if (!nix && (pkt_secs - attempt->seq_start) >= 10)
		{
		
			/* Do we know the hostname? */
			if (attempt->srchost)
			{
				/* Log the hostname */
				vprint("%s (%s): sequence timeout (stage %d)\n", attempt->src, attempt->srchost, attempt->stage);
				logprint("%s (%s): sequence timeout (stage %d)\n", attempt->src, attempt->srchost, attempt->stage);
			}
			else
			{
				/* Log the IP */
				vprint("%s: sequence timeout (stage %d)\n", attempt->src, attempt->stage);
				logprint("%s: sequence timeout (stage %d)\n", attempt->src, attempt->stage);
			}
			nix = 1;
		}

		/* If clear flag is set */
		if (nix)
		{
			free(attempt->cred);
			/* splice this entry out of the list */
			if (lp->prev)
				lp->prev->next = lp->next;
			if (lp->next)
				lp->next->prev = lp->prev;
			/* If lp is the only element of the list then empty the list */
			if (lp == attempts)
				attempts = NULL;
			lp->prev = lp->next = NULL;
			if (attempt->srchost)
			{
				free(attempt->srchost);
				attempt->srchost = NULL;
			}
			list_free(lp);
		}

		lp = lpnext;
	}

	attempt = NULL;
	/* look for this guy in our attempts list */
	for (lp = attempts; lp; lp = lp->next)
	{
		knocker_t *att = (knocker_t *)lp->data;
		if (!strcmp(src_ip, att->src))
		{
			found_attempts = list_add(found_attempts, att);
		}
	}

	if (found_attempts == NULL)
	{
		found_attempts = list_add(found_attempts, NULL);
	}

	for (found_attempt = found_attempts; found_attempt != NULL; found_attempt = found_attempt->next)
	{
		attempt = (knocker_t *)found_attempt->data;
		found_attempt->data = NULL;

		if (attempt)
		{
			// int flagsmatch = flags_match(attempt->door, ip_proto, tcp);
			if (/*flagsmatch && ip_proto == attempt->door->protocol[attempt->stage] &&*/
				dport == attempt->cred->keySequence[attempt->stage])
			{
				process_attempt(attempt);
				//} else if(flagsmatch == 0) {
				/* TCP flags didn't match -- just ignore this packet, don't
				 * invalidate the knock.
				 */
			}
			else
			{
				/* invalidate the knock sequence, it will be removed in the
				 * next sniff() call.
				 */
				attempt->stage = -1;
			}
		}
		else
		{
			/* did they hit the first port correctly? */
			for (lp = credentials; lp; lp = lp->next)
			{
				credential_t *cred = (credential_t *)lp->data;

				/* if we're working with TCP, try to match the flags */
				if (tcp->th_flags & TH_SYN)
				{
					tcp_port_tries++;
					if (tcp_port_tries != 1)
						continue; // skipping duplicate SYN packets
				}
				if (/*ip_proto == door->protocol[0] &&*/ dport == cred->keySequence[0] /*&&
					!target_strcmp(dst_ip, door->target)*/
				)
				{
					struct hostent *he;
					/* create a new entry */
					attempt = (knocker_t *)malloc(sizeof(knocker_t));
					if (attempt == NULL)
					{
						perror("malloc");
						exit(1);
					}
					attempt->from_ipv6 = from_ipv6;
					attempt->srchost = NULL;
					strcpy(attempt->src, src_ip);
					/* try a reverse lookup if enabled  */
					if (o_lookup)
					{
						if (from_ipv6 == 0)
						{
							inaddr.s_addr = ip->ip_src.s_addr;
							he = gethostbyaddr((void *)&inaddr, sizeof(inaddr), AF_INET);
						}
						else
						{
							he = gethostbyaddr((void *)&ip6->ip6_src, sizeof(ip6->ip6_src), AF_INET6);
						}
						if (he)
						{
							attempt->srchost = strdup(he->h_name);
						}
					}

					attempt->stage = 0;
					attempt->seq_start = pkt_secs;
					attempt->cred = cred;
					attempts = list_add(attempts, attempt);
					if (!attempt->stage)
					{
						vprint("Failed to add new attempt to the list");
					}
					else
					{
						vprint("New attempt added to the list");
					}
					process_attempt(attempt);
				}
			}
		}
	}

	list_free(found_attempts);
	tcp_port_tries = 0; // Reset the SYN packet counter after processing
}

/* Compare ip against door target or all ips of our local interface
 */
int target_strcmp(char *ip, char *target)
{
	ip_literal_t *myip;

	if (target && !strcmp(ip, target))
		return 0;

	if (target)
		return 1;

	for (myip = myips; myip != NULL; myip = myip->next)
	{
		if (!strcmp(ip, myip->value))
			return 0;
	}

	return 1;
}

/* vim: set ts=2 sw=2 noet:*/

void generate_new_sequence(credential_t *cred)
{
	// We are going to generate a random name between 4 and 16 for the sequence size
	printf("Generating new sequence...\n");
	unsigned char size_buf[1];
	if (RAND_bytes(size_buf, sizeof(size_buf)) != 1)
	{
		perror("RAND_bytes");
		cleanup(1);
	}
	int size = (size_buf[0] % 13) + 4; // random size between 4 and 16
	unsigned short *sequence = malloc(size * sizeof(unsigned short));
	if (sequence == NULL)
	{
		perror("malloc");
		cleanup(1);
	}
	for (int i = 0; i < size; i++)
	{
		unsigned char buf[2];
		if (RAND_bytes(buf, sizeof(buf)) != 1)
		{
			perror("RAND_bytes");
			cleanup(1);
		}
		unsigned short num = 10000 + ((buf[0] << 8) | buf[1]) % (65535 - 10000 + 1);
		sequence[i] = num;
	}
	printf("Generated sequence!\n");
	printf("Sequence: ");
	printf("Testing size: %d\n", sizeof(*sequence) / sizeof(unsigned short));
	for (int i = 0; i < size; i++)
	{
		printf("%hu ", sequence[i]);
	}
	cred->keySequence = sequence;
	cred->keySequenceCount = size;
	printf("\nSequence size: %d\n", cred->keySequenceCount);
}

//ERROR: here is the anchor IP
void send_sequence(credential_t *cred, char *topic, unsigned int port, char *sailerIP)
{
	// We are going to generate a random name between 4 and 16 for the sequence size
	char url[40];

	snprintf(url, sizeof(url), "ssl://127.0.0.1:%i", 8883);
	MQTTClient client;
	int rc = MQTTClient_create(&client, url, "Anchor", MQTTCLIENT_PERSISTENCE_NONE, NULL);

	if (rc != MQTTCLIENT_SUCCESS)
		vprint("creation error %i", rc);

	char *size_str = malloc(10 * sizeof(char));
	snprintf(size_str, sizeof(size_str), "%d", cred->keySequenceCount);

	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;

	MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
	ssl_opts.trustStore = "ca.crt"; // Path to your CA certificate
	ssl_opts.enableServerCertAuth = 0; // Disable server certificate authentication
	ssl_opts.sslVersion = MQTT_SSL_VERSION_TLS_1_2; // Use TLS 1.2
	conn_opts.ssl = &ssl_opts;

	rc = MQTTClient_connect(client, &conn_opts);

	if (rc != MQTTCLIENT_SUCCESS)
		vprint("connection error %i", rc);

	vprint("Connected to MQTT broker at %s with topic %s\n", url, topic);

	// Initialize the content buffer as an empty string
	sleep(1); // Wait for the connection to be established
	rc = MQTTClient_publish(client, topic, sizeof(size_str), size_str, 2, 0, NULL);
	MQTTClient_yield();
	if (rc != MQTTCLIENT_SUCCESS)
	{
		vprint("publish error %i", rc);
		MQTTClient_disconnect(client, 1000);
		MQTTClient_destroy(&client);
		return;
	}
	char *sequence_str = malloc(6);
	for (int i = 0; i < cred->keySequenceCount; i++)
	{
		snprintf(sequence_str, 6, "%hu", cred->keySequence[i]);
		rc = MQTTClient_publish(client, topic, strlen(sequence_str), sequence_str, 2, 0, NULL);
		MQTTClient_yield();
		vprint("Published %s to topic %s\n", sequence_str, topic);
		if (rc != MQTTCLIENT_SUCCESS)
		{
			vprint("publish error %i", rc);
			MQTTClient_disconnect(client, 1000);
			MQTTClient_destroy(&client);
			return;
		}
	}
	rc = MQTTClient_publish(client, topic, strlen(cred->anchorTopic), cred->anchorTopic, 2, 0, NULL);
	MQTTClient_yield();
	if (rc != MQTTCLIENT_SUCCESS)
	{
		vprint("publish error %i", rc);
		MQTTClient_disconnect(client, 1000);
		MQTTClient_destroy(&client);
		return;
	}
	rc = MQTTClient_publish(client, topic, strlen(cred->sailerTopic), cred->sailerTopic, 2, 0, NULL);
	MQTTClient_yield();
	if (rc != MQTTCLIENT_SUCCESS)
	{
		vprint("publish error %i", rc);
		MQTTClient_disconnect(client, 1000);
		MQTTClient_destroy(&client);
		return;
	}
	char *port_str = malloc(6);
	snprintf(port_str, 6, "%hu", port);
	vprint("Publishing port %s to topic %s\n", port_str, topic);
	rc = MQTTClient_publish(client, topic, strlen(port_str), port_str, 2, 0, NULL);
	if (rc != MQTTCLIENT_SUCCESS)
	{
		vprint("publish error %i", rc);
		MQTTClient_disconnect(client, 1000);
		MQTTClient_destroy(&client);
		return;
	}
}

unsigned short *receive_sequence(char *topic, unsigned int port)
{
	MQTTClient client;

	vprint("Receiving seq...");

	unsigned short *toret = malloc(SEQ_MAX * sizeof(unsigned short));
	if (toret == NULL)
	{
		fprintf(stderr, "Failed to allocate memory for sequence\n");
		return NULL;
	}

	char url[40];
	snprintf(url, sizeof(url), "ssl://%s:%u", "127.0.0.1", 8883);
	vprint("Connecting to MQTT broker at %s with topic %s\n", url, topic);

	int rc = MQTTClient_create(&client, url, "KnockKnock", MQTTCLIENT_PERSISTENCE_NONE, NULL);
	if (rc != MQTTCLIENT_SUCCESS)
	{
		fprintf(stderr, "Failed to create MQTT client, return code: %d\n", rc);
		return NULL;
	}

	MQTTClient_connectOptions conn_opts = MQTTClient_connectOptions_initializer;
	MQTTClient_SSLOptions ssl_opts = MQTTClient_SSLOptions_initializer;
	ssl_opts.trustStore = "ca.crt"; // Path to your CA certificate
	ssl_opts.enableServerCertAuth = 0; // Disable server certificate authentication
	ssl_opts.sslVersion = MQTT_SSL_VERSION_TLS_1_2; // Use TLS 1.2
	conn_opts.ssl = &ssl_opts;

	rc = MQTTClient_connect(client, &conn_opts);
	if (rc != MQTTCLIENT_SUCCESS)
	{
		fprintf(stderr, "Failed to connect, return code: %d\n", rc);
		MQTTClient_destroy(&client);
		return NULL;
	}

	rc = MQTTClient_subscribe(client, topic, 2);
	if (rc != MQTTCLIENT_SUCCESS)
	{
		fprintf(stderr, "Failed to subscribe to topic %s, return code: %d\n", topic, rc);
		MQTTClient_disconnect(client, 1000);
		MQTTClient_destroy(&client);
		return NULL;
	}

	MQTTClient_message *message = NULL;
	char *topicName = NULL;
	int topicLen = 0;
	int i = 0;

	do
	{
		rc = MQTTClient_receive(client, &topicName, &topicLen, &message, 5000);
		if (rc == MQTTCLIENT_SUCCESS && message != NULL)
		{
			vprint("Received seq: %s\n", message->payload);
			if (strcmp(message->payload, "END_SEQUENCE") == 0)
			{
				printf("End of sequence received, exiting...\n");
				break; // Exit if the end of sequence message is received
			}
			toret[i] = atoi((char *)message->payload);
			MQTTClient_freeMessage(&message);
			i++;
		}
		else if (rc != MQTTCLIENT_SUCCESS)
		{
			fprintf(stderr, "Failed to receive message, return code: %d\n", rc);
			break;
		}
	} while (1);

	MQTTClient_disconnect(client, 1000);
	MQTTClient_destroy(&client);

	return toret;
}

void secondPhaseManager(knocker_t *sealer)
{
	credential_t *new_cred = generate_new_credentials(sealer->cred);
	vprint("Size of credentials vector: %d\n", list_count(credentials));

	open_mqtt_port(*sealer);
	sleep(1); // Syncing time
	send_sequence(new_cred, sealer->cred->anchorTopic, sealer->cred->MQTT_port, sealer->src);
	sleep(1); // Syncing time
	

	unsigned short *received_sequence = receive_sequence(sealer->cred->sailerTopic, sealer->cred->MQTT_port);
	if(fork() == 0) {
		search_and_exec(received_sequence, sealer->src);
		exit(0);
	}
		
	unvalidate_credentials(sealer->cred);
	credentials = list_add(credentials, new_cred);
	close_mqtt_port(*sealer);
	generate_pcap_filter(); /* update pcap filter */
}

credential_t *generate_new_credentials()
{
	// Generate new credentials
	credential_t *cred = malloc(sizeof(credential_t));
	if (cred == NULL)
	{
		perror("malloc");
		cleanup(1);
	}
	generate_new_sequence(cred);
		unsigned char rand_bytes[4];

	if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1)
	{
		perror("RAND_bytes");
		cleanup(1);
	}
	cred->MQTT_port = 1024 + (rand_bytes[0] << 8 | rand_bytes[1]) % (9999 - 1024 + 1);
	if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1)
	{
		perror("RAND_bytes");
		cleanup(1);
	}
	unsigned int rand_val = (rand_bytes[0] << 24) | (rand_bytes[1] << 16) | (rand_bytes[2] << 8) | rand_bytes[3];
	snprintf((char *)cred->anchorTopic, sizeof(cred->anchorTopic), "knockd/%08x", rand_val);
	if (RAND_bytes(rand_bytes, sizeof(rand_bytes)) != 1)
	{
		perror("RAND_bytes");
		cleanup(1);
	}
	rand_val = (rand_bytes[0] << 24) | (rand_bytes[1] << 16) | (rand_bytes[2] << 8) | rand_bytes[3];
	snprintf((char *)cred->sailerTopic, sizeof(cred->sailerTopic), "knockd/%08x", rand_val);

	return cred;
}

void search_and_exec(unsigned short *sequence, char* sailerIP)
{
	vprint("Searching for sequence...\n");
	PMList *lp;
	int found = 0;
	for (lp = doors; lp; lp = lp->next)
	{
		opendoor_t *door = (opendoor_t *)lp->data;
		if (door->one_time_sequences_fd)
		{
			vprint("Door %s has one-time sequences, skipping...\n", door->name);
			continue;
		}
		found = 1; // Assume we found the sequence
		vprint("Checking door %s\n", door->name);
		for (int i = 0; i < door->seqcount; i++)
		{
			if (door->sequence[i] != sequence[i])
			{
				found = 0;
				break;
			}
		}
		if (found)
		{
			//TODO: parse the command and execute it after, if not %IP% and other rules doesn't work
			vprint("Found matching sequence for door %s\n", door->name);
			char parsed_cmd[PATH_MAX];
			if (door->start_command6 && sailerIP && strchr(sailerIP, ':')) {
				// If the door has an IPv6 command and the IP looks like IPv6, use it
				parse_cmd(parsed_cmd, sizeof(parsed_cmd), door->start_command6, sailerIP);
			} else {
				parse_cmd(parsed_cmd, sizeof(parsed_cmd), door->start_command, sailerIP);
			}
			//parse_cmd(parsed_cmd, sizeof(parsed_cmd), door->start_command, sailerIP);
			exec_cmd(parsed_cmd, door->name);
			if(door->stop_command)
			{
				char parsed_stop_cmd[PATH_MAX];
				if (door->stop_command6 && sailerIP && strchr(sailerIP, ':')) {
					parse_cmd(parsed_stop_cmd, sizeof(parsed_stop_cmd), door->stop_command6, sailerIP);
				} else {
					parse_cmd(parsed_stop_cmd, sizeof(parsed_stop_cmd), door->stop_command, sailerIP);
				}
				//parse_cmd(parsed_stop_cmd, sizeof(parsed_stop_cmd), door->stop_command, sailerIP);
				sleep(door->cmd_timeout);
				exec_cmd(parsed_stop_cmd, door->name);
			}
			return;
		}
	}
}