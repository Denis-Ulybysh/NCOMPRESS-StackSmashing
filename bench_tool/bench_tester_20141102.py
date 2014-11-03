#!/usr/bin/python
# Developed by: Denis Ulybyshev and Servio Palacios 
# This tool will help to test vulnerabilities 
# Some ideas taken from: RIPE
# First draft: 2014-10-22, just skeleton

import os
import sys

#Pointer used
codePointer = ["return", "baseptr"] ;

funcs = ["memcpy", "strcpy", "strncpy", "sprintf","strcat"];

#We just handle Stack or Buffer Overflows
locations = ["stack","heap",];
attacks = ["segmentationfault", "returnintolibc", "outputfile"];

techniques = []
repeatTimes = 0

#Checking Arguments
if len(sys.argv) < 2:
	print "Usage: python "+sys.argv[0] + " [direct|indirect|both] <number of times to repeat each test>"
	sys.exit(1)

else:
	if sys.argv[1] == "both":
		techniques = ["direct","indirect"];
	else:
		techniques = [sys.argv[1]];

	repeat_times = int(sys.argv[2]);

#if Directory of our Benchmarking tool does not exists, create it
i = 0
if not os.path.exists("/bench-eval"):
	os.system("mkdir /bench-eval");
os.system('sysctl -w kernel.va_randomize_space=0')

total_ok=0;
total_fail=0;
total_some=0;
total_np = 0;


for attack in attacks:
	for tech in techniques:
		for loc in locations:
			for ptr in codePointer:
				for func in funcs:
					i = 0
					s_attempts = 0
					attack_possible = 1
					while i < repeat_times:
						i += 1

						os.system("rm /tmp/bench_log")
						cmdline = "./build/bench_attack_generator -t "+tech+" -i "+attack+" -c " + ptr + "  -l " + loc +" -f " + func + " > /tmp/bench_log 2>&1"
						os.system(cmdline)
						log = open("/tmp/bench_log","r")
		

						if log.read().find("Impossible") != -1:
							print cmdline,"\t\t","NOT POSSIBLE"
							attack_possible = 0;
							break;	#Not possible once, not possible always :)


						if os.path.exists("/bench-eval/f_xxxx"):
							s_attempts += 1		
							os.system("rm /becnh-eval/f_xxxx")


					if attack_possible == 0:
						total_np += 1;
						continue

					if s_attempts == repeat_times:
						print cmdline,"\t\tOK\t", s_attempts,"/",repeat_times
						total_ok += 1;
					elif s_attempts == 0:
						print cmdline,"\t\tFAIL\t",s_attempts,"/",repeat_times
						total_fail += 1;
					else:
						print cmdline,"\t\tSOMETIMES\t", s_attempts,"/",repeat_times
						total_some +=1;
						

total_attacks = total_ok + total_some + total_fail + total_np;
print "\n||Summary|| OK: ",total_ok," ,SOME: ",total_some," ,FAIL: ",total_fail," ,NP: ",total_np," ,Total Attacks: ",total_attacks

						
					


