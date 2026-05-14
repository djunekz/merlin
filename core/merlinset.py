import os, sys
from datetime import datetime, date, timedelta
from merlincolor import *
from __init__ import __version__, __author__

auth    = """{}{}{}""".format(LM, __author__, N)
version = """{}{}{}""".format(LM, __version__, N)

now   = datetime.now()
today = now.strftime("%A, %B %d, %Y")
jam   = now.strftime("%H:%M:%S")
waktu = """{}Time {}: {}{}{} """.format(LY, W, LM, jam, N)
tgl   = """{}Date {}: {}{}{} """.format(LY, W, LM, today, N)

sukses  = """{}[{}√{}]{}""".format(LC, LG, LC, LG)
error   = """{}[{}!{}]{}""".format(LC, LR, LC, R)
danger  = """{}[{}ERROR{}] {}-{} status {}-{}""".format(LC, LR, LC, N, W, N, LR)
warning = """{}[{}WARNING{}] {}-{} info {}-{}""".format(LC, LY, LC, N, W, N, LY)
plus    = """{}[{}+{}]{}""".format(LC, LY, LC, W)
min_pfx = """{}[{}-{}]{}""".format(LC, LY, LC, LY)
star    = """{}[{}GET{}]{}""".format(LC, LY, LC, LY)
info    = """{}[{}INFO{}]{}""".format(LC, C, LC, C)
err     = """{}[{}!{}]{}""".format(G, LR, G, R)
note    = """{}[{}*{}]{}""".format(LG, LY, LG, W)
