/*
Hooker firewall by ak3M is made available under the GNU GPL v 2.0 license.
*/

#define _GNU_SOURCE

#include <dlfcn.h>
#include <stdio.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>              
#include <sys/socket.h>
#include <netinet/in.h>
#include <unistd.h>

#include <netdb.h>
#include <arpa/inet.h>
#include <errno.h>

#include <string.h>

#include <termios.h>
#include <sys/time.h>

#include <time.h>

// #define QNETHOOK_DEBUG

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
// OVERRIDING STATUS.
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
// commented ones will not be overriden.

//#define OVR_socket
//#define OVR_socketpair
//#define OVR_bind
//#define OVR_getsockname
#define OVR_connect			////
//	#define OVR_getpeername
//#define OVR_send
//#define OVR_recv
//#define OVR_sendto		////
//#define OVR_recvfrom		////
//#define OVR_sendmsg
//#define OVR_recvmsg
//	#define OVR_getsockopt
//	#define OVR_setsockopt
//#define OVR_listen
//#define OVR_accept

#ifdef __USE_GNU
//#define OVR_accept4
#endif

//#define OVR_shutdown

#ifdef __USE_XOPEN2K
//#define OVR_sockatmark
#endif

#ifdef __USE_MISC
//#define OVR_isfdtype
#endif

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
// ORIGINAL FUNCTIONS POINTERS.
// straight from socket.h
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

#ifdef OVR_socket
int (*orig_socket) (int __domain, int __type, int __protocol);
#endif

#ifdef OVR_socketpair
int (*orig_socketpair) (int __domain, int __type, int __protocol,
		       int __fds[2]);
#endif

#ifdef OVR_bind
int (*orig_bind) (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);
#endif

#ifdef OVR_getsockname
int (*orig_getsockname) (int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len);
#endif

#ifdef OVR_connect
int (*orig_connect) (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len);
#endif

#ifdef OVR_getpeername
int (*orig_getpeername) (int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len);
#endif

#ifdef OVR_send
ssize_t (*orig_send) (int __fd, __const void *__buf, size_t __n, int __flags);
#endif

#ifdef OVR_recv
ssize_t (*orig_recv) (int __fd, void *__buf, size_t __n, int __flags);
#endif

#ifdef OVR_sendto
ssize_t (*orig_sendto) (int __fd, __const void *__buf, size_t __n,
		       int __flags, __CONST_SOCKADDR_ARG __addr,
		       socklen_t __addr_len);
#endif

#ifdef OVR_recvfrom
ssize_t (*orig_recvfrom) (int __fd, void *__restrict __buf, size_t __n,
			 int __flags, __SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len);
#endif

#ifdef OVR_sendmsg
ssize_t (*orig_sendmsg) (int __fd, __const struct msghdr *__message,
			int __flags);
#endif

#ifdef OVR_recvmsg
ssize_t (*orig_recvmsg) (int __fd, struct msghdr *__message, int __flags);
#endif

#ifdef OVR_getsockopt
int (*orig_getsockopt) (int __fd, int __level, int __optname,
		       void *__restrict __optval,
		       socklen_t *__restrict __optlen);
#endif

#ifdef OVR_setsockopt
int (*orig_setsockopt) (int __fd, int __level, int __optname,
		       __const void *__optval, socklen_t __optlen);
#endif

#ifdef OVR_listen
int (*orig_listen) (int __fd, int __n);
#endif

#ifdef OVR_accept
int (*orig_accept) (int __fd, __SOCKADDR_ARG __addr,
		   socklen_t *__restrict __addr_len);
#endif

#ifdef __USE_GNU
#ifdef OVR_accept4
int (*orig_accept4) (int __fd, __SOCKADDR_ARG __addr,
		    socklen_t *__restrict __addr_len, int __flags);
#endif
#endif

#ifdef OVR_shutdown
int (*orig_shutdown) (int __fd, int __how);
#endif

#ifdef __USE_XOPEN2K
#ifdef OVR_sockatmark
int (*orig_sockatmark) (int __fd);
#endif
#endif

#ifdef __USE_MISC
#ifdef OVR_isfdtype
int (*orig_isfdtype) (int __fd, int __fdtype);
#endif
#endif

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
// QNETHOOK.
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

short getRule(char *report); // Forward

// Generic net data field struct to report basic informations,
// some fields might be empty, unknown or useless depending of the action.
#define BUFSIZE_ACTION		64
#define BUFSIZE_FAMILY		32
#define BUFSIZE_IP			64
#define BUFSIZE_DNS		64
#define BUFSIZE_PORT		6
#define BUFSIZE_PROTOCOL	32
#define BUFSIZE_MESSAGE	512

typedef struct {
	char action[BUFSIZE_ACTION];				// action requested (listen, bind, connect, ...)
	char family[BUFSIZE_FAMILY];				// AF_INET, UNIX...
	char ip[BUFSIZE_IP];							// IP
	char dns[BUFSIZE_DNS];						// name lookup
	char port[BUFSIZE_PORT];					// port
	char protocol[BUFSIZE_PROTOCOL];		// protocol TCP, UDP...
	char message[BUFSIZE_MESSAGE];			// additional information
} hooker_report;

#define BUFSIZE_NAME 192					// max string size for name or path
#define _EMPTY_QNETHOOK_FIELD_ ""		// empty field

// Process informations struct: PID and cmdline as reported by /proc
typedef struct {
	pid_t pid; 										// process id
	pid_t ppid; 										// parent process id
	char name[BUFSIZE_NAME];				// process name
	char pname[BUFSIZE_NAME];				// parent process name
} hooker_procinfo;

// Process name from PID using proc FS.
void getProcessNameByPID(pid_t pid, char *s)
{
	// get process name from proc
	int fd, sizeRead;
	char path[BUFSIZE_NAME] = {""};
	snprintf(path, BUFSIZE_NAME, "/proc/%d/cmdline", (int) pid);

	fd = open(path, O_RDONLY);
	if( fd == -1 ){
		sprintf(s, _EMPTY_QNETHOOK_FIELD_);
#ifdef QNETHOOK_DEBUG
		fprintf(stderr, "QNETHOOK:ERROR:Cannot open proc cmdline for process ID %d.\n", (int) pid);
#endif
	}else{
		sizeRead = read(fd, s, BUFSIZE_NAME);
		if(sizeRead == -1){
#ifdef QNETHOOK_DEBUG
		fprintf(stderr, "QNETHOOK:ERROR:Cannot read proc cmdline for process ID %d.\n", (int) pid);
#endif
		}
		close(fd);
    }
}

// Process informations.
void getProcessInfo(hooker_procinfo *procinfo)
{
	procinfo->pid = getpid();
	procinfo->ppid = getppid();
	getProcessNameByPID(procinfo->pid, &(procinfo->name[0]));
	getProcessNameByPID(procinfo->ppid, &(procinfo->pname[0]));
}

// Removes all char x from *s
void removeCharFromString(char *s, char x)
{
	int i, j;
	for(i = 0; s[i] != 0; ++i ){
		while(s[i]==x){ // Copy all chars, including NULL at end, over char to left
			j=i;
			while(s[j]!=0){
				s[j]=s[j+1];
				++j;
			}
		}
	}
}

// Trigger the GUI, so that the user can authorize or refuse the current action.
short hooker_authorize(hooker_report *hookerinfo)
{

// PID max chars, name max size, [...], + separators...
#define BUFSIZE_REPORT	\
	12 + \
	BUFSIZE_NAME		+	\
	12 + \
	BUFSIZE_NAME		+	\
	BUFSIZE_ACTION		+	\
	BUFSIZE_FAMILY		+	\
	BUFSIZE_IP		+	\
	BUFSIZE_DNS		+	\
	BUFSIZE_PORT		+	\
	BUFSIZE_PROTOCOL		+	\
	BUFSIZE_MESSAGE + \
	12

	
	char report[BUFSIZE_REPORT];
	short result;
    
	hooker_procinfo procinfo;
	getProcessInfo(&procinfo);
  
	// We don't want '\t' because we use it as field separator when sending data
	char badChars[2] = { '\t', '\n' };
	int i;
	for(i = 0; i < 2; i++){
		removeCharFromString((char *) &procinfo.name, badChars[i]);
		removeCharFromString((char *) &procinfo.pname, badChars[i]);

		removeCharFromString((char *) &hookerinfo->action, badChars[i]);
		removeCharFromString((char *) &hookerinfo->family, badChars[i]);
		removeCharFromString((char *) &hookerinfo->ip, badChars[i]);
		removeCharFromString((char *) &hookerinfo->port, badChars[i]);
		removeCharFromString((char *) &hookerinfo->dns, badChars[i]);
		removeCharFromString((char *) &hookerinfo->protocol, badChars[i]);
		if(badChars[i] != '\n'){ // New line is ok for message (additional information box)
			removeCharFromString((char *) &hookerinfo->message, badChars[i]);
		}
	}

#ifdef QNETHOOK_DEBUG
	fprintf(stderr, "Process Informations:\n");
	fprintf(stderr, "  name, PID: \"%s\" (%d)\n", procinfo.name, (int) procinfo.pid);
	fprintf(stderr, "  parent,PPID: \"%s\" (%d)\n", procinfo.pname, (int) procinfo.ppid);
	fprintf(stderr, "  action, family, protocol: \"%s\" \"%s\" \"%s\"\n", hookerinfo->action, hookerinfo->family, hookerinfo->protocol); 
	fprintf(stderr, "  IP:port, DNS: %s:%s (\"%s\")\n", hookerinfo->ip, hookerinfo->port, hookerinfo->dns);
	fprintf(stderr, "  message: \"%s\"\n", hookerinfo->message);
#endif

	//"testProg1\t12345\tbash\t54321\t	socket\tTCP\tAF_INET\t192.168.45.1\t80\tlocalhost\tdefault message testing."
	snprintf (report,
			BUFSIZE_REPORT,
            "%s\t%d\t%s\t%d\t%s\t%s\t%s\t%s\t%s\t%s\t%s\n",
            procinfo.name,
            procinfo.pid,
            procinfo.pname,
            procinfo.ppid,
            hookerinfo->action,
            hookerinfo->protocol,
            hookerinfo->family,
            hookerinfo->ip,
            hookerinfo->port,
            hookerinfo->dns,
            hookerinfo->message
          );

	if( (strcmp(hookerinfo->family, "AF_INET")) && (strcmp(hookerinfo->family, "AF_INET6")) ){
		return 0;
	}
	if( (!strcmp(hookerinfo->family, "AF_INET6")) &&
		(!strcmp(hookerinfo->ip, "::")) ){
		return 0;
	}
	if( (!strcmp(hookerinfo->family, "AF_INET")) &&
		(!strcmp(hookerinfo->ip, "127.0.0.1")) ){
		return 0;
	}
	
	result = getRule(&report[0]);
	return result;
}

void getHost(char *name, char *ip)
{
	struct sockaddr sa;
	int ret = getnameinfo(&sa, sizeof(sa), name, BUFSIZE_DNS, NULL, 0, 0);
	if(ret){
			snprintf(name, BUFSIZE_DNS, "%s", "Cannot resolve name."); // Can't resolve
	}
}

char *getFamilyName(int sa_family)
{
	switch(sa_family){
//  	  case AF_LOCAL	: return "AF_LOCAL";
//                         	break;
		case AF_UNIX		: 	return "AF_UNIX";
							break;
//  	  case AF_FILE		:	return "AF_FILE";
//                          break;
		case AF_INET			:	return "AF_INET";
							break;
		case AF_INET6		:	return "AF_INET6";
							break;
		case AF_UNSPEC	:	return "AF_UNSPEC";
							break;
	}
	return "UNLISTED";
}

char *getSocketTypeName(int socktype)
{
   switch (socktype)
   {
		case SOCK_STREAM			:	return "TCP";
									break;
		case SOCK_DGRAM				:	return "UDP";
									break;
		case SOCK_SEQPACKET		:	return "SEQPACKET";
									break;
		case SOCK_RAW				:	return "RAW";
									break;
		case SOCK_RDM					:	return "RDM";
									break;
		case SOCK_PACKET			:	return "PACKET";
									break;
   }
   return "UNLISTED";
}

char *getProtocolName(int protocol)
{
	switch(protocol){
		case IPPROTO_IP				: 	return "IPPROTO_IP";
										break;
//    case IPPROTO_HOPOPTS	: return "IPPROTO_HOPOPTS";
//                                  break;
		case IPPROTO_ICMP			: 	return "IPPROTO_ICMP";
										break;
		case IPPROTO_IGMP			: 	return "IPPROTO_IGMP";
										break;
		case IPPROTO_IPIP				: 	return "IPPROTO_IPIP";
										break;
		case IPPROTO_TCP				: 	return "IPPROTO_TCP";
										break;
		case IPPROTO_EGP				: 	return "IPPROTO_EGP";
										break;
		case IPPROTO_PUP				: 	return "IPPROTO_PUP";
										break;
		case IPPROTO_UDP				: 	return "IPPROTO_UDP";
										break;
		case IPPROTO_IDP				: 	return "IPPROTO_IDP";
										break;
		case IPPROTO_TP				:	return "IPPROTO_TP";
										break;
		case IPPROTO_DCCP			: 	return "IPPROTO_DCCP";
										break;
		case IPPROTO_IPV6			:	return "IPPROTO_IPV6";
										break;
		case IPPROTO_ROUTING		: 	return "IPPROTO_ROUTING";
										break;
		case IPPROTO_FRAGMENT	: 	return "IPPROTO_FRAGMENT";
										break;
		case IPPROTO_RSVP			: 	return "IPPROTO_RSVP";
										break;
		case IPPROTO_GRE				:	return "IPPROTO_GRE";
										break;
		case IPPROTO_ESP				:	return "IPPROTO_ESP";
										break;
		case IPPROTO_AH				:	return "IPPROTO_AH";
										break;
		case IPPROTO_ICMPV6		:	return "IPPROTO_ICMPV6";
										break;
		case IPPROTO_NONE			: 	return "IPPROTO_NONE";
										break;
		case IPPROTO_DSTOPTS		: 	return "IPPROTO_DSTOPTS";
										break;
		case IPPROTO_MTP				: 	return "IPPROTO_MTP";
										break;
		case IPPROTO_ENCAP			: 	return "IPPROTO_ENCAP";
										break;
		case IPPROTO_PIM				: 	return "IPPROTO_PIM";
										break;
		case IPPROTO_COMP			: 	return "IPPROTO_COMP";
										break;
		case IPPROTO_SCTP			: 	return "IPPROTO_SCTP";
										break;
		case IPPROTO_UDPLITE		: 	return "IPPROTO_UDPLITE";
										break;
		case IPPROTO_RAW			: 	return "IPPROTO_RAW";
										break;
	}
	return "UNLISTED";
}

char *getSocketFamilyfromFD(int __fd)
{
	struct sockaddr sa;
	size_t len;
	getsockname(__fd, &sa, (socklen_t *) &len);   
	return getFamilyName(sa.sa_family);
}

// Get protocol name from socket file descriptor, STREAM(TCP) or DATAGRAM(UDP) or RAW.
char *getSocketProtocolFromFD(int __fd)
{
	// get protocol from socket, STREAM(TCP) or DATAGRAM(UDP)...
	unsigned int optlen;
	int gs, socktype;
	optlen = sizeof(socktype);
#ifdef OVR_getsockopt
	gs = orig_getsockopt (__fd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
#else
	gs = getsockopt (__fd, SOL_SOCKET, SO_TYPE, &socktype, &optlen);
#endif
	if (gs == -1){		// error
		socktype = -1;
	}
	return getSocketTypeName(socktype);
}

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
// OVERRIDING.
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

// clean all hook info fields
#define CLEAN_QNETHOOK_FIELDS(hookerinfo) 	\
	sprintf(hookerinfo.action, _EMPTY_QNETHOOK_FIELD_);	\
	sprintf(hookerinfo.family, _EMPTY_QNETHOOK_FIELD_);	\
	sprintf(hookerinfo.ip, _EMPTY_QNETHOOK_FIELD_);	\
	sprintf(hookerinfo.port, _EMPTY_QNETHOOK_FIELD_);	\
	sprintf(hookerinfo.dns, _EMPTY_QNETHOOK_FIELD_);	\
	sprintf(hookerinfo.protocol, _EMPTY_QNETHOOK_FIELD_);\
	sprintf(hookerinfo.message, _EMPTY_QNETHOOK_FIELD_);

// simple hook, will only report the function name
#define SIMPLE_NAME_HOOK(funcname) 	\
	snprintf(hookerinfo.action, BUFSIZE_ACTION, funcname);

void hookerInfosFrom(hooker_report *hookerinfo, int __fd, struct sockaddr_in *sockaddr)
{
	// hooker infos ----------- >>
	sprintf(hookerinfo->action, "connect");
	// family
	int f = sockaddr->sin_family;
	sprintf(hookerinfo->family, "%s", getFamilyName(f) );
	// ip port 
	if((f == AF_INET) || (f == AF_INET6)){
		sprintf(hookerinfo->ip, "%s", inet_ntop(f, (const void * __restrict__) &((struct sockaddr_in *) sockaddr)->sin_addr,  hookerinfo->ip, BUFSIZE_IP));
		sprintf(hookerinfo->port, "%d", ntohs(sockaddr->sin_port));
		getHost(hookerinfo->dns, hookerinfo->ip);
		sprintf(hookerinfo->protocol, "%s", getSocketProtocolFromFD(__fd));	
	}else{
		sprintf(hookerinfo->ip, _EMPTY_QNETHOOK_FIELD_);
		sprintf(hookerinfo->port, _EMPTY_QNETHOOK_FIELD_);
		sprintf(hookerinfo->dns, _EMPTY_QNETHOOK_FIELD_);
		sprintf(hookerinfo->protocol, _EMPTY_QNETHOOK_FIELD_);
	}
	sprintf(hookerinfo->message, _EMPTY_QNETHOOK_FIELD_);
  // hooker infos ----------- <<
}

#ifdef OVR_socket
/* Create a new socket of type TYPE in domain DOMAIN, using
   protocol PROTOCOL.  If PROTOCOL is zero, one is chosen automatically.
   Returns a file descriptor for the new socket, or -1 for errors.  */
int socket (int __domain, int __type, int __protocol)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("socket");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_socket (__domain, __type, __protocol);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_socketpair
/* Create two new sockets, of type TYPE in domain DOMAIN and using
   protocol PROTOCOL, which are connected to each other, and put file
   descriptors for them in FDS[0] and FDS[1].  If PROTOCOL is zero,
   one will be chosen automatically.  Returns 0 on success, -1 for errors.  */
int socketpair (int __domain, int __type, int __protocol,
		       int __fds[2])
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK(socketpair);
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_socketpair (__domain, __type, __protocol,
		       __fds);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_bind
/* Give the socket FD the local address ADDR (which is LEN bytes long).  */
int bind (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("bind");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_bind ( __fd, __addr, __len);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_getsockname
/* Put the local address of FD into *ADDR and its length in *LEN.  */
int getsockname (int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("getsockname");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_getsockname (__fd, __addr,
			 __len);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_connect
/* Open a connection on socket FD to peer at ADDR (which LEN bytes long).
   For connectionless socket types, just set the default address to send to
   and the only address from which to accept transmissions.
   Return 0 on success, -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
int connect (int __fd, __CONST_SOCKADDR_ARG __addr, socklen_t __len)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	hookerInfosFrom(&hookerinfo, __fd, (struct sockaddr_in *) __addr.__sockaddr__);
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_connect (__fd, __addr, __len);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_getpeername
/* Put the address of the peer connected to socket FD into *ADDR
   (which is *LEN bytes long), and its actual length into *LEN.  */
int getpeername (int __fd, __SOCKADDR_ARG __addr,
			socklen_t *__restrict __len)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("getpeername");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_getpeername ( __fd, __addr,
			 __len);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_send
/* Send N bytes of BUF to socket FD.  Returns the number sent or -1.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
ssize_t send (int __fd, __const void *__buf, size_t __n, int __flags)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("send");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_send ( __fd, __buf, __n, __flags);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_recv
/* Read N bytes into BUF from socket FD.
   Returns the number read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
ssize_t recv (int __fd, void *__buf, size_t __n, int __flags)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("recv");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_recv (__fd, __buf, __n, __flags);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_sendto
/* Send N bytes of BUF on socket FD to peer at address ADDR (which is
   ADDR_LEN bytes long).  Returns the number sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
ssize_t sendto (int __fd, __const void *__buf, size_t __n,
		       int __flags, __CONST_SOCKADDR_ARG __addr,
		       socklen_t __addr_len)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	hookerInfosFrom(&hookerinfo, __fd, (struct sockaddr_in *) &(__addr.__sockaddr__));
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_sendto (__fd, __buf, __n,
		       __flags, __addr,
		       __addr_len);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_recvfrom
/* Read N bytes into BUF through socket FD.
   If ADDR is not NULL, fill in *ADDR_LEN bytes of it with tha address of
   the sender, and store the actual size of the address in *ADDR_LEN.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
ssize_t recvfrom (int __fd, void *__restrict __buf, size_t __n,
			 int __flags, __SOCKADDR_ARG __addr,
			 socklen_t *__restrict __addr_len)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	hookerInfosFrom(&hookerinfo, __fd, (struct sockaddr_in *) &(__addr.__sockaddr__));
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_recvfrom ( __fd,  __buf, __n,
			 __flags,  __addr,
			 __addr_len);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_sendmsg
/* Send a message described MESSAGE on socket FD.
   Returns the number of bytes sent, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
ssize_t sendmsg (int __fd, __const struct msghdr *__message,
			int __flags)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("sendmsg");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_sendmsg ( __fd, __message,
			 __flags);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_recvmsg
/* Receive a message as described by MESSAGE from socket FD.
   Returns the number of bytes read or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
ssize_t recvmsg (int __fd, struct msghdr *__message, int __flags)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("recvmsg");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_recvmsg (__fd, __message, __flags);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_getsockopt
/* Put the current value for socket FD's option OPTNAME at protocol level LEVEL
   into OPTVAL (which is *OPTLEN bytes long), and set *OPTLEN to the value's
   actual length.  Returns 0 on success, -1 for errors.  */
int getsockopt (int __fd, int __level, int __optname,
		       void *__restrict __optval,
		       socklen_t *__restrict __optlen)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("getsockopt");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_getsockopt ( __fd, __level, __optname,
		       __optval,
		        __optlen);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_setsockopt
/* Set socket FD's option OPTNAME at protocol level LEVEL
   to *OPTVAL (which is OPTLEN bytes long).
   Returns 0 on success, -1 for errors.  */
int setsockopt (int __fd, int __level, int __optname,
		       __const void *__optval, socklen_t __optlen)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("setsockopt");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_setsockopt (__fd, __level, __optname,
		       __optval, __optlen);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_listen
/* Prepare to accept connections on socket FD.
   N connection requests will be queued before further requests are refused.
   Returns 0 on success, -1 for errors.  */
int listen (int __fd, int __n)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("listen");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_listen (__fd, __n);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef OVR_accept
/* Await a connection on socket FD.
   When a connection arrives, open a new socket to communicate with it,
   set *ADDR (which is *ADDR_LEN bytes long) to the address of the connecting
   peer and *ADDR_LEN to the address's actual length, and return the
   new socket's descriptor, or -1 for errors.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
int accept (int __fd, __SOCKADDR_ARG __addr,
		   socklen_t *__restrict __addr_len)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("accept");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_accept (__fd, __addr,
		    __addr_len);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef __USE_GNU
#ifdef OVR_accept4
/* Similar to 'accept' but takes an additional parameter to specify flags.

   This function is a cancellation point and therefore not marked with
   __THROW.  */
int accept4 (int __fd, __SOCKADDR_ARG __addr,
		    socklen_t *__restrict __addr_len, int __flags)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("accept4");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_accept4 (__fd, __addr,
		     __addr_len, __flags);
	}
	errno = EINVAL;
	return -1;
}
#endif
#endif

#ifdef OVR_shutdown
/* Shut down all or part of the connection open on socket FD.
   HOW determines what to shut down:
     SHUT_RD   = No more receptions;
     SHUT_WR   = No more transmissions;
     SHUT_RDWR = No more receptions or transmissions.
   Returns 0 on success, -1 for errors.  */
int shutdown (int __fd, int __how)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("shutdown");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_shutdown ( __fd,  __how);
	}
	errno = EINVAL;
	return -1;
}
#endif

#ifdef __USE_XOPEN2K
#ifdef OVR_sockatmark
/* Determine wheter socket is at a out-of-band mark.  */
int sockatmark (int __fd)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("sockatmark");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_sockatmark ( __fd);
	}
	errno = EINVAL;
	return -1;
}
#endif
#endif


#ifdef __USE_MISC
#ifdef OVR_isfdtype
/* FDTYPE is S_IFSOCK or another S_IF* macro defined in <sys/stat.h>;
   returns 1 if FD is open on an object of the indicated type, 0 if not,
   or -1 for errors (setting errno).  */
int isfdtype (int __fd, int __fdtype)
{
	short auth = 0;
	hooker_report hookerinfo;
	CLEAN_QNETHOOK_FIELDS(hookerinfo);
	SIMPLE_NAME_HOOK("isfdtype");
	auth = hooker_authorize(&hookerinfo);
	if(auth != -1){
		return orig_isfdtype (__fd, __fdtype);
	}
	errno = EINVAL;
	return -1;
}
#endif
#endif

//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////
// GET RULE.
//////////////////////////////////////////////////////////////////////////////
//////////////////////////////////////////////////////////////////////////////

#define BUFSIZE 64
#define HOSTNAME "127.0.0.1"
#define PORT 25252
short getRule(char *report)
{
	int sockfd, n;
	struct sockaddr_in serveraddr;
	struct hostent *server;
	char buf[BUFSIZE];

	// socket: create the socket
#ifdef OVR_socket
	sockfd = orig_socket(AF_INET, SOCK_STREAM, 0);
#else
	sockfd = socket(AF_INET, SOCK_STREAM, 0);
#endif
	if (sockfd < 0) {
#ifdef QNETHOOK_DEBUG
		fprintf(stderr, "QNETHOOK:ERROR:Opening socket\n");
#endif
		return -1;
	}
	// gethostbyname: get the server's DNS entry
	server = gethostbyname(HOSTNAME);
	if (server == NULL) {
#ifdef QNETHOOK_DEBUG
		fprintf(stderr, "QNETHOOK:ERROR:No such host \"%s\"\n", HOSTNAME);
#endif
		return -1;
	}
	bzero((char *) &serveraddr, sizeof(serveraddr));
	serveraddr.sin_family = AF_INET;
	bcopy((char *)server->h_addr, (char *)&serveraddr.sin_addr.s_addr, server->h_length);
	serveraddr.sin_port = htons(PORT);
	// connect
#ifdef OVR_connect
	if (orig_connect(sockfd, &serveraddr, sizeof(serveraddr)) < 0) {
#else
	if (connect(sockfd, &serveraddr, sizeof(serveraddr)) < 0) {
#endif

#ifdef QNETHOOK_DEBUG
		fprintf(stderr, "QNETHOOK:ERROR:Connecting\n");
#endif
		return -1;
	}
	// send report
	n = write(sockfd, report, strlen(report));
	if (n < 0) {
#ifdef QNETHOOK_DEBUG
		fprintf(stderr, "QNETHOOK:ERROR:Writing to socket\n");
#endif
		return -1;
	}
	// server's reply
	bzero(buf, BUFSIZE);
	n = read(sockfd, buf, BUFSIZE);
	
close(sockfd);
	
	if (n < 0) {
#ifdef QNETHOOK_DEBUG
		fprintf(stderr, "QNETHOOK:ERROR:Reading from socket\n");
#endif
		return -1;
	}
	if(!strcmp(buf, "true\n")) {	// ACCEPT
		return 0;
	}
////	close(sockfd);
	return -1;
}

//void __attribute__ ((constructor)) my_init(void);
//void __attribute__ ((destructor)) my_fini(void);

void _init(void)
{
#ifdef OVR_socket
  orig_socket = dlsym(RTLD_NEXT, "socket");
#endif
#ifdef OVR_socketpair
  orig_socketpair = dlsym(RTLD_NEXT, "socketpair");
#endif
#ifdef OVR_bind
  orig_bind = dlsym(RTLD_NEXT, "bind");
#endif
#ifdef OVR_getsockname
  orig_getsockname = dlsym(RTLD_NEXT, "getsockname");
#endif
#ifdef OVR_connect
  orig_connect = dlsym(RTLD_NEXT, "connect");
#endif
#ifdef OVR_getpeername
  orig_getpeername = dlsym(RTLD_NEXT, "getpeername");
#endif
#ifdef OVR_send
  orig_send = dlsym(RTLD_NEXT, "send");
#endif
#ifdef OVR_recv
  orig_recv = dlsym(RTLD_NEXT, "recv");
#endif
#ifdef OVR_sendto
  orig_sendto = dlsym(RTLD_NEXT, "sendto");
#endif
#ifdef OVR_recvfrom
  orig_recvfrom = dlsym(RTLD_NEXT, "recvfrom");
#endif
#ifdef OVR_sendmsg
  orig_sendmsg = dlsym(RTLD_NEXT, "sendmsg");
#endif
#ifdef OVR_recvmsg
  orig_recvmsg = dlsym(RTLD_NEXT, "recvmsg");
#endif
#ifdef OVR_getsockopt
  orig_getsockopt = dlsym(RTLD_NEXT, "getsockopt");
#endif
#ifdef OVR_setsockopt
  orig_setsockopt = dlsym(RTLD_NEXT, "setsockopt");
#endif
#ifdef OVR_listen
  orig_listen = dlsym(RTLD_NEXT, "listen");
#endif
#ifdef OVR_accept
  orig_accept = dlsym(RTLD_NEXT, "accept");
#endif

#ifdef __USE_GNU
#ifdef OVR_accept4
  orig_accept4 = dlsym(RTLD_NEXT, "accept4");
#endif
#endif

#ifdef OVR_shutdown
  orig_shutdown = dlsym(RTLD_NEXT, "shutdown");
#endif

#ifdef __USE_XOPEN2K
#ifdef OVR_sockatmark
  orig_sockatmark = dlsym(RTLD_NEXT, "sockatmark");
#endif
#endif

#ifdef __USE_MISC
#ifdef OVR_isfdtype
  orig_isfdtype = dlsym(RTLD_NEXT, "isfdtype");
#endif
#endif

#ifdef QNETHOOK_DEBUG
  fprintf(stderr, "QNETHOOK:REGISTERED\n");
#endif
}

void my_fini(void)
{
}
