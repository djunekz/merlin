import os, sys
from datetime import *
from merlincolor import *

auth="""{}djunekz{}""".format(LM,N)
version="""{}1.0.0{}""".format(LM,N)

now = datetime.now()
today = now.strftime("%A, %B %d, %Y")
jam = now.strftime("%H:%M:%S")
waktu="""{}Time {}: {}{}{} """.format(LY,W,LM,jam,N)
tgl="""{}Date {}: {}{}{} """.format(LY,W,LM,today,N)

sukses="""{}[{}√{}]{}""".format(LC,LG,LC,LG)
error="""{}[{}!{}]{}""".format(LC,LR,LC,R)
danger="""{}[{}ERROR{}] {}-{} status {}-{}""".format(LC,LR,LC,N,W,N,LR)
warning="""{}[{}WARNING{}] {}-{} info {}-{}""".format(LC,LY,LC,N,W,N,LY)
plus="""{}[{}+{}]{}""".format(LC,LY,LC,W)
min="""{}[{}-{}]{}""".format(LC,LY,LC,LY)
star="""{}[{}GET{}]{}""".format(LC,LY,LC,LY)
info="""{}[{}INFO{}]{}""".format(LC,C,LC,C)
err="""{}[{}!{}]{}""".format(G,LR,G,R)
note="""{}[{}*{}]{}""".format(LG,LY,LG,W)
