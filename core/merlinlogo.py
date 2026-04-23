import os, sys, time
from merlinset import *

logo="""
{}Author {}: {}
{}Date   {}: {}2025 July 1             {}
{}Version{}: {}                   {}
{}---------------------------------------------------------------
{}  ___      ___   _______   _______   ___      __   ____  ____
 ({}"{}  \\    /{}"{}  | /{}"{}      | /{}"{}      \\ |{}"{}  |    |{}"{} \\ (\\{}"{}  \\|{}"{}   |
  \\   \\  /{}/{}   |({}:{} ______)|{}:{}        ||{}|{}  |    |{}|{}  ||{}.{}\\   \\    |
  /\\   \\/{}.{}    | \\/      ||_____/   )|{}:{}  |    |{}:{}  ||{}:{} \\{}.{}  \\   |
 |{}:{} \\{}.{}        | // _____) //      /  \\  |___ |{}.{}  ||{}.{}  \\   \\{}.{} |
 |{}.{}  \\    /{}:{}  |({}:{}       ||{}:{}  __   \\ ( \\_|{}:{}  \\|   ||    \\   \\ |
 |___|\\__/|___| \\_______)|__|  \\___) \\_______)\\___)\\___|\\___\\)

{}For analyst website vulnerability scanner
{}---------------------------------------------------------------
{}{}This tool has been created using Python and Termux Emulator.
Have a look at: {}{}{}https://github.com/djunekz/merlin{}
{}{}
This tool is used to analyze website vulnerabilitie.
Permission is hereby granted to analyze private property,
not to be used in any illegal manner without the owner's consent.{}
{}---------------------------------------------------------------
""".format(LY,W,auth,LY,W,LM,waktu,LY,W,version,tgl,LM,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LM,D,W,LB,D,U,N,D,W,N,LM)

menu="""{}[{}1{}]{}{} Check WP Vuln{}
{}[{}2{}]{}{} Check SQLi Vuln{}
{}[{}3{}]{}{} WebShake Check{}
{}[{}4{}]{}{} Web Analyzer{}
{}[{}5{}]{}{} Settings / Config{}
{}[{}6{}]{}{} Check Update{}
{}[{}x{}]{}{} exit{}
""".format(G,W,G,LY,D,N,G,W,G,LY,D,N,G,W,G,LY,D,N,G,W,G,LY,D,N,G,W,G,LY,D,N,G,W,G,LY,D,N,G,R,G,LR,D,N)

menu1="""
"""

menu2="""
"""
