#!/usr/bin/env ruby
# Main menu
require 'io/console'
require 'socket'
require 'timeout'

$debug = 1
$quit = false
$filtering = true
$logs = []

$term_columns = 80

$display_about = false

$thread_socket = nil
$popup_input = nil

$log_filename = "hooker.log"
$log_file = File.open($log_filename, "w")


################################################################################
##################################################
# RULES (~/.hooker.conf)
# Format of the "R_" tables following:
# Let say we have 2 applications, "prog1" and "prog2",
# prog1 has 3 rules, and prog 2 has 2, here is what the tables could look like:
#	$R_APPNAME		= [			      "prog1", 															"prog2"							]
#	$R_ACTION		= [  [        "connect",                  "bind",  	"socket" 	],				[		"connect", 		"*" 		]		]
#	$R_TRUST		= [	 [                  "0",                      "0",         "1"  	],		    	[       	      1,   		 0 	]       ]
#	$R_IP			= [	 [ "192.168.1.2",   "192.168.1.10",         "/.*/"  		],			    [           "/.*/", 		"/.*/" 	]       ]
#	$R_PORT			= [	 [				  "80",                 "1458",         "/.*/" 	],				[           "/.*/", 		"/.*/" 	]       ]
#	$R_FAMILY		= [	 [       "AF_INET",             "AF_INET",        "/.*/"  	], 			    [    "AF_UNIX", 		"/.*/" 	]       ]
#	$R_PROTOCOL		= [	 [				"TCP",                 "TCP",           "/.*/" 	],				[           "/.*/", 		"/.*/" 	]       ]

$R_APPNAME = []			# 1D : applications' cmdlines as reported in /proc
$R_TRUST = []			# 2D : 1 to trust or 0 to block
$R_ACTION = []			# 2D : library call (connect, bind, ....)
$R_IP = []			# 2D : IP
$R_PORT = []			# 2D : port
$R_FAMILY = []			# 2D : family
$R_PROTOCOL = []		# 2D : protocol

$R_CONFIG_FILE = "~/.hooker.conf"

# Load rules from config file
def loadRules()
	_log("Loading rules.")
	configFile = File.expand_path($R_CONFIG_FILE)
	if not File.exists?(configFile) then
		_log("WARNING: rules file \"#{configFile}\" does not exist.")
		return false
	end

	begin
		fcontent = File.open(configFile,"r") {|io| io.read}
	rescue
		_log("ERROR: cannot read rules file \"#{configFile}\" -> #{$!}")
		return false
	end

	$R_APPNAME.clear
	$R_TRUST.clear
	$R_ACTION.clear
	$R_IP.clear
	$R_PORT.clear
	$R_FAMILY.clear
	$R_PROTOCOL.clear
	
	loadingAppName = ""
	appID = -1
	fcontent.split("\n").each(){ |l|
#puts "l=#{l}"
		l = l.lstrip.rstrip
		if l =~ /^cmdline>/ then
			loadingAppName = l.gsub(/(.*)\"(.*)\"/, '\2')
			if $debug == 1 then
				_log("Loading app: \"#{loadingAppName}\"")
			end
			appID += 1
							
			$R_APPNAME += [ loadingAppName ]

			$R_TRUST += [[]]
			$R_ACTION += [[]]
			$R_IP += [[]]
			$R_PORT += [[]]
			$R_FAMILY += [[]]
			$R_PROTOCOL += [[]]

		elsif  loadingAppName != "" then # rules
			r = l.split("\t")
			if(r.size < 7) or (r[6] != '.') then
				if $debug == 1 then
					_log("Skipping rule: #{l}")
				end
			end
			p r.inspect
			if	(r[0] == "0") or (r[0] == "1") then
				if $debug == 1 then
					_log("Loading rule: #{l}")
				end
				$R_TRUST[appID] += [r[0]]
				$R_ACTION[appID] += [r[1]]
				$R_IP[appID] += [r[2]]
				$R_PORT[appID] += [r[3]]
				$R_FAMILY[appID] += [r[4]]
				$R_PROTOCOL[appID] += [r[5]]

			end
		end
	}
	if $debug == 2 then
		_log($R_APPNAME.inspect)
		_log($R_TRUST.inspect)
		_log($R_ACTION.inspect)
		_log($R_IP.inspect)
		_log($R_PORT.inspect)
		_log($R_FAMILY.inspect)
		_log($R_PROTOCOL.inspect)
	end
	return true
end

# Write rules to config file
def saveRules()
	_log("Saving rules.")
	configFile = File.expand_path($R_CONFIG_FILE)

	begin
		f = File.open(configFile,"w")
		lines = "# This file is generated automaticly by Hooker.\n"
		0.upto($R_APPNAME.size - 1){ |appID|
			lines += "cmdline>\"#{$R_APPNAME[appID]}\"\n"
			0.upto($R_TRUST[appID].size - 1){ |i|
				rule = [
							$R_TRUST[appID][i],
							$R_ACTION[appID][i],
							$R_IP[appID][i],
							$R_PORT[appID][i],
							$R_FAMILY[appID][i],
							$R_PROTOCOL[appID][i]
						  ]
				lines += "\t#{rule[0]}\t#{rule[1]}\t#{rule[2]}\t#{rule[3]}\t#{rule[4]}\t#{rule[5]}\t.\n"
			}
		}
		f.write(lines)
		f.close
	rescue
		_log("ERROR: cannot save rules file \"#{configFile}\" -> #{$!}")
		return false
	end
	return true
end

# Return true if testString match regexString
# regexString must be enclosed in '/' to be treated as regex.
def regexTestRule(regexString, testString)
	r = regexString.dup
	if	(r[0,1] == '/') and
		(r[r.size - 1,1] == '/') then
		r[0] = ""
		r[r.size - 1] = ""
		begin
			if (testString =~ /#{r}/) then
				return true
			end
		rescue
			_log("ERROR: invalid regexp  \"#{r}\" -> #{$!}")
		end
	end
	return false
end

# Return [appID, ruleID] if a rule match or nil.
# strict == true treat regexp has real values(not interpreted, strict rule match).
# trust == -1 to ignore trust value check(rule testing): see testRuleMatching()
def hasRule(app = "/.*/", trust = "-1", action = "/.*/", ip = "/.*/", port = "/.*/", family = "/.*/", protocol = "/.*/", strict = false)
	0.upto($R_APPNAME.size() - 1){ |appID|
		if ( ($R_APPNAME[appID] == app) or ((regexTestRule($R_APPNAME[appID], app) == true) and (strict == false)) ) then
			# app found
			0.upto($R_TRUST[appID].size() - 1){ |i|
			
				ret = [false, false, false, false ] # trust, action, ip, port

				rule = [
							$R_TRUST[appID][i],
							$R_ACTION[appID][i],
							$R_IP[appID][i],
							$R_PORT[appID][i],
							$R_FAMILY[appID][i],
							$R_PROTOCOL[appID][i]
						  ]

				if(rule[0] == trust) or (trust == "-1") then ret[0] = true end
				if rule[1] == action then ret[1] = true end
				if rule[2] == ip then ret[2] = true end
				if rule[3] == port then ret[3] = true end
				if rule[4] == family then ret[4] = true end
				if rule[5] == protocol then ret[5] = true end

				# adjust strict
				if (strict == false) then
					if (regexTestRule(rule[1], action) == true) then ret[1] = true end
					if (regexTestRule(rule[2], ip) == true) then ret[2] = true end
					if (regexTestRule(rule[3], port) == true) then ret[3] = true end
					if (regexTestRule(rule[4], family) == true) then ret[4] = true end
					if (regexTestRule(rule[5], protocol) == true) then ret[5] = true end
				end

				if  (ret[0] == true) and 
					(ret[1] == true) and
					(ret[2] == true) and
					(ret[3] == true) and
					(ret[4] == true) and
					(ret[5] == true) then
					return [appID, i]
				end
			}
			if strict == true then
				break # strict == we can break, otherwise other potential appnames regexps might match.
			end
		end
	}
	return nil
end

# Return first matching IDs or nil
def testRuleMatching(app, action, ip, port, family, protocol, strict = false)
	ret = hasRule(app, trust = "-1", action, ip, port, family, protocol, strict) # trust to -1 when testing rule, that's what we are looking for.
	if ret != nil then
		appID, ruleID = ret[0], ret[1]
#		trusted = $R_TRUST[appID][ruleID] == "1" ? true : false
		return [ appID, ruleID ]
	end
	return nil  # no rule matching
end
 
def addRule(app, trust, action , ip, port, family, protocol)
	appID = -1
	0.upto($R_APPNAME.size() - 1){ |i|
		if ($R_APPNAME[i] == app) then
			# app found
			appID = i
			break
		end
	}
	if (appID == -1) then
			appID = $R_APPNAME.size
			addApp(app)
	end
	$R_TRUST[appID] += [trust]
	$R_ACTION[appID] += [action]
	$R_IP[appID] += [ip]
	$R_PORT[appID] += [port]
	$R_FAMILY[appID] += [family]
	$R_PROTOCOL[appID] += [protocol]
end

def delRuleByID(appID, ruleID)
	if(appID < 0) or (appID >= $R_APPNAME.size) then
		return false # wrong ID
	end
	if(ruleID < 0) or (ruleID >= $R_TRUST[appID].size) then
		return false # wrong ID
	end
	$R_TRUST[appID].delete_at(ruleID)
	$R_ACTION[appID].delete_at(ruleID)
	$R_IP[appID].delete_at(ruleID)
	$R_PORT[appID].delete_at(ruleID)
	$R_FAMILY[appID].delete_at(ruleID)
	$R_PROTOCOL[appID].delete_at(ruleID)
	return true # rule removed
end

def delRule(app, trust, action, ip, port, family, protocol)
	ret = hasRule(app, trust, action, ip, port, strict = true)
	if ret != nil then
		appID, ruleID = ret[0], ret[1]	
		delRuleByID(appID, ruleID)
		return true # rule removed
	end
	return false # rule not found
end

def addApp(app)
	$R_APPNAME += [ app ]
	$R_TRUST += [[]]
	$R_ACTION += [[]]
	$R_IP += [[]]
	$R_PORT += [[]]
	$R_FAMILY += [[]]
	$R_PROTOCOL += [[]]
end

def delAppByID(appID)
	if(appID < 0) or (appID >= $R_APPNAME.size) then
		return false # wrong ID
	end
	$R_APPNAME.delete_at(appID)
	$R_TRUST.delete_at(appID)
	$R_ACTION.delete_at(appID)
	$R_IP.delete_at(appID)
	$R_PORT.delete_at(appID)
	$R_FAMILY.delete_at(appID)
	$R_PROTOCOL.delete_at(appID)
	return true
end

def delApp(app)
	appID = -1
	0.upto($R_APPNAME.size() - 1){ |i|
		if ($R_APPNAME[i] == app) then
			# app found
			appID = i
			break
		end
	}
	if(appID == -1) then
		return false
	end
	delAppByID(appID)	
	return true
end

################################################################################



# TCP listener thread wait for C wrapper data to generate and enqueue new popups
netThread = Thread.new do
	server = TCPServer.open 25252
	_log("Thread : Listening on port 25252.")
	loop {
		$thread_socket = server.accept

		if $filtering == true then
			begin
				line = $thread_socket.gets
				l = line.split("\t")
				if l.size < 11 then
					$thread_socket.puts "ERROR: 11 elements needed separated with tab.\n"
				else
					#Format:
					#		app = l[0], pid = l[1],
					#		parentApp = l[2], parentPid = l[3],
					#		action = l[4], protocol = l[5], family = l[6],
					#		ip = l[7], port = l[8], dns = l[9],
					#		message = l[10])
					ret = testRuleMatching(app = l[0], action = l[4], ip = l[7], port = l[8], family = l[6], protocol = l[5], strict = false) # set strict to true to disable regexp matching
					_log("Thread : TESTING \"#{l[0]}\" action(#{l[4]}) IP(#{l[7]}) port(#{l[8]}) family(#{l[6]}) protocol(#{l[5]})")
					if ret != nil then					# ---------ok we found a rule matching this ----------------------------------- AUTO RULE MATCHING
						appID, ruleID = ret[0], ret[1]
						trusted = $R_TRUST[appID][ruleID] == "1" ? true : false
						_log("Thread : FOUND RULE [#{appID}, #{ruleID}] for \"#{l[0]}\" [ PID(#{l[1]}) action(#{l[4]}) IP(#{l[7]}) port(#{l[8]}) family(#{l[6]}) protocol(#{l[5]}) msg(#{l[10].chomp}) ]")
						$thread_socket.puts trusted # return value to external wrapper
					else							# ---------no rule, enqueue popup and wait for user to answer ----------------- USER ANSWER NEEDED
						$display_popup = true
						$popup_input = l
						# the input screen must set $popup_input to nil when it is done
						# so we can continue later(note that it will also write to socket outside of this thread)
						while($popup_input != nil) do
							sleep(0.2)
						end
					end
				end
			rescue
				_log("Thread: ERROR: Thread : TCP listener : #{$!}")
			end
		else # not filtering
			$thread_socket.puts true
		end
		$thread_socket.close
	}
end
################################################################################
$_p_action=false
$_p_ip=false
$_p_port=false
$_p_protocol=false
$_p_family=false
$_p_remember=false
$_p_all=false
def _display_popup()
	system("clear")
	puts "#{Time.now}"
	puts ""
	puts "#{$popup_input}"
	puts ""
	puts "[#{$_p_action}]A(c)tion  [#{$_p_protocol}]Pr(o)tocol"
	puts "[#{$_p_ip}](I)P      [#{$_p_family}](F)amily  "
	puts "[#{$_p_port}](P)ort    (A)ll     "
	puts ""
	puts "[#{$_p_remember}](R)emember"
	puts ""
	puts "[(T)rust]"
	puts "[(B)lock]"
end

def _add_rule_popup_macro(trust = "0")	
	l = $popup_input
	####(app = l[0], action = l[4], ip = l[7], 
	####port = l[8], family = l[6], protocol = l[5], 
	addRule(l[0], 
		trust,
		$_p_action == true ? l[4] : "/.*/" ,
		$_p_ip == true ? l[7] : "/.*/"  , 
		$_p_port == true ? l[8] : "/.*/" , 
		$_p_family == true ? l[6] : "/.*/" , 
		$_p_protocol == true ? l[5] : "/.*/")
	_log("Added new rule for #{l[0]}.")
end

def _input_popup()
	input = STDIN.getch
	if(input == 'c') then
		$_p_action = !$_p_action
	elsif(input == 'o') then
		$_p_protocol = !$_p_protocol
	elsif(input == 'i') then
		$_p_ip = !$_p_ip
	elsif(input == 'f') then
		$_p_family = !$_p_family
	elsif(input == 'p') then
		$_p_port = !$_p_port
	elsif(input == 'a') then
		$_p_action=$_p_ip=$_p_port=$_p_protocol=$_p_family=$_p_all=!$_p_all
	elsif(input == 'r') then
		$_p_remember = !$_p_remember
	elsif(input == 't') then
		begin
			if($_p_remember == true) then
				_add_rule_popup_macro(trust = "1")
				saveRules()
			end
			$thread_socket.puts true
		rescue Exception => detail
                	_log("_input_popup():Cannot send to socket:" + detail.message())
		end
		$popup_input = nil
	elsif(input == 'b') then
		begin
			if($_p_remember == true) then
				_add_rule_popup_macro(trust = "0")
				saveRules()
			end
			$thread_socket.puts false
		rescue Exception => detail
                	_log("_input_popup():Cannot send to socket:" + detail.message())
		end
		$popup_input = nil
	end
end

def _display_about()
	system("clear")
	puts "About:"
	puts ""
	puts "Hooker firewall overrides some net related syscalls in the userspace"
	puts "(using a small library), then this script is able to allow or refuse"
	puts "network access to other applications."
	puts "+Runtime authorisations +Regular expressions"
	puts "See README file to check how to write additional rules manually."
	puts "License is GNU GPL V 2.0."
	puts ""
	puts "[(M)ain screen]"
end

def _input_about()
	input = STDIN.getch
	if(input == 'm') or (input == 'q') then
		$display_about = false
	end
end

def _log(s)
	l = "#{Time.new.strftime("%Y/%m/%d-%H:%M:%S")} > #{s}"
	$log_file.write(l + "\n")
	$logs += [ l ]
end

def _printLogs()
	if($logs.size == 0) then return end
	lineid = $logs.size - 10
	if(lineid < 0) then lineid = 0 end
	
	0.upto(9){ |i|
		l = $logs[lineid]
		if(l.size >= $term_columns) then
			l = l[0..$term_columns - 3] + "..."
		end
		puts l
		lineid += 1
		if(lineid == $logs.size) then
			break
		end
	}
end

def _display_main()
	system("clear")
	puts ""
	puts "[1-Filtering] status: #{$filtering}"
	puts "[2-About]"
	puts "[3-Exit]"
	puts ""
	puts "\nLogs:"
	puts ""
	_printLogs()
end

def _input_main()
	input = STDIN.getch
	if(input == '1') then
		_log("key 1 pressed.")
		$filtering = !$filtering
	elsif(input == '2') then
		_log("key 3 pressed.")
		$display_about = true
	elsif(input == '3') or (input == 'q') then
		_log("key 4 pressed.")
		_log("Quit.")
		$quit = true
	end
end
################################################################################

loadRules()

while $quit == false do	
	#################################################
	if($popup_input != nil) then
		_display_popup()
		# we wait X seconds for input, otherwise we redraw the screen
		begin
			Timeout.timeout(1) do
				_input_popup()
			end
		rescue Timeout::Error
		#rescue
		end
		next
	end
	#################################################	
	if($display_about == true) then
		_display_about()
		# we wait X seconds for input, otherwise we redraw the screen
		begin
			Timeout.timeout(1) do
				_input_about()
			end
		rescue Timeout::Error
		#rescue
		end
		next
	end
	#################################################
	_display_main()
	# we wait X seconds for input, otherwise we
	# redraw the screen (in order to update screen logs)
	begin
		Timeout.timeout(1) do
			_input_main()
		end
	rescue Timeout::Error
	#rescue
	end
end

$log_file.close

# read a line from stdin:
# 	s=STDIN.gets
