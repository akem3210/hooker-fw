Hooker firewall
--------------------------------------------------------------------------------
ABOUT:
--------------------------------------------------------------------------------
Userspace application-level firewall.
It works by overriding and filtering some network library calls.
It is written in C and ruby.
--------------------------------------------------------------------------------
INSTALL:
--------------------------------------------------------------------------------
Build the library (used to override syscalls):

 > sh build.sh

Run the ruby app:

 > ruby hooker.rb

Then in a second terminal, from the hooker folder,
wrapp some application via LD_PRELOAD using:

 > LD_PRELOAD=./hooker.so <APPLICATION> <PARAMETERS>

Example with Firefox: (Empty Firefox cache first)

 > LD_PRELOAD=./hooker.so firefox www.example.com

In the ruby app screen you will get some request for every connection 
attempted by firefox and you'll be able to allow or refuse the connection, 
you can use "Remember" to save it as a rule.
uncheck "IP" and all IPs on current port/family/protocol will then be
automaticly accepted.
 
It is also possible to install the library onto the system so that
every application will be filtered no matter how it is launched,
note that in that case network access to applications will be blocked 
until explicitly allowed by the user(via hooker.rb) or via rules in the 
config file.
(Think about boot time network access for some applications).
There is no support for separate users which means the hooker.rb app
first launched will receive all connections request from all users,
root or any other user.

Install:
(as root)

 > sh build.sh install

Uninstall:
(as root)

 > sh build.sh uninstall

--------------------------------------------------------------------------------
CONFIGURATION:
--------------------------------------------------------------------------------
Rules are defined in $HOME/.hooker.conf
String values enclosed with '/' are considered regexp (see Ruby Regexp)

Format: (values separated by '\t', note the terminating '.')

	cmdline>"NAME(String)"
	Trust(1 or 0)\tAction(String)\tIP(String)\tPort(String)\tFamily(String)\tProtocol(String)\t.

Example:

	cmdline>"/usr/bin/ftp"
		1	connect		127.0.0.1		21	AF_INET	TCP	.
		0	recvfrom	/.*/			80	/.*/	TCP	.
