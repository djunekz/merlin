#!/usr/bin/python3
import sys, time
from __init__ import __version__, __author__, __github__

N  = '\33[0m'
DG = '\33[90m'
LR = '\33[1;91m'
LG = '\33[1;92m'
LY = '\33[1;93m'
LB = '\33[1;94m'
LM = '\33[1;95m'
LC = '\33[1;96m'
W  = '\33[1;97m'
BG = '\33[102m'
U  = '\33[4m'

warn    = LG + '[' + LR + '!' + LG + ']'
min_pfx = LC + '[' + LR + 'ERROR' + LC + ']'
plus    = LG + '[' + LY + '+' + LG + ']'
pss     = LC + '[' + DG + 'PROCESS' + LC + ']'
star    = LC + '[' + LY + 'GET' + LC + ']'
sukses  = LG + '[' + W + '√' + LG + ']'
vs      = W + '(' + LY + __version__ + '#' + __author__ + W + ')' + LR
lnk     = DG + U + __github__.replace('https://', '') + N
sss     = (W + 'There are two possibilities where the website is limited '
           'by Cloudflare or the connection is unstable.' + N)

def banner():
    print(f'''{W}
{W} _ _ _ _____ _____ {LR}    _       _       
{W}| | | |   __| __  |{LR}___| |_ ___| |_ ___  {vs}
{W}| | | |   __| __ -|{LR}_ -|   | .'| '_| -_| 
{W}|_____|_____|_____|{LR}___|_|_|__,|_,_|___| {lnk}
    {LY}W E B  C R A W L E R  &  A N A L Y Z E R{LG}
''')
