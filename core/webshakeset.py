#!/usr/bin/python3
import sys, time

# Color
N='\33[0m'
DG='\33[90m'
LR='\33[1;91m'
LG='\33[1;92m'
LY='\33[1;93m'
LB='\33[1;94m'
LM='\33[1;95m'
LC='\33[1;96m'
W='\33[1;97m'
BG='\33[102m'
U='\33[4m'
warn= LG + '[' + LR + '!' + LG + ']'
min= LC + '[' + LR + 'ERROR' + LC + ']'
plus= LG + '[' + LY + '+' + LG + ']'
pss= LC + '[' + DG + 'PROCESS' + LC + ']'
star= LC + '[' + LY + 'GET' + LC + ']'
sukses= LG + '[' + W + '√' + LG + ']'
vs= W + '(' + LY + '1.0.0#djunekz' + W + ')' + LR
lnk= DG + U + 'github.com/djunekz/webshake' + N
sss=W + 'There are two possibilities where the website is limited by Cloudflare or the connection is unstable.' +N

# Banner

def banner():
    print(f'''{W}
{W} _ _ _ _____ _____ {LR}    _       _       
{W}| | | |   __| __  |{LR}___| |_ ___| |_ ___  {vs}
{W}| | | |   __| __ -|{LR}_ -|   | .'| '_| -_| 
{W}|_____|_____|_____|{LR}___|_|_|__,|_,_|___| {lnk}
    {LY}W E B  S C A N  A N A L Y Z E R{LG}
''')
