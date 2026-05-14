import os, sys, time
from merlinset import *
from __init__ import __version__, __author__, __github__

logo = """
{}Author {}: {}
{}Create {}: {}2025 July 1             {}
{}Version{}: {}{}{}                   {}
{}---------------------------------------------------------------
{}  ___      ___   _______   _______   ___      __   ____  ____
 ({}\"{}  \\    /{}\"{}  | /{}\"{}      | /{}\"{}      \\ |{}\"{}  |    |{}\"{} \\ (\\{}\"{}  \\|{}\"{}   |
  \\   \\  /{}/{}   |({}:{} ______)|{}:{}        ||{}|{}  |    |{}|{}  ||{}.{}\\   \\    |
  /\\   \\/{}.{}    | \\/      ||_____/   )|{}:{}  |    |{}:{}  ||{}:{} \\{}.{}  \\   |
 |{}:{} \\{}.{}        | // _____) //      /  \\  |___ |{}.{}  ||{}.{}  \\   \\{}.{} |
 |{}.{}  \\    /{}:{}  |({}:{}       ||{}:{}  __   \\ ( \\_|{}:{}  \\|   ||    \\   \\ |
 |___|\\__/|___| \\_______)|__|  \\___) \\_______)\\___)\\___|\\___\\)

{}For analyst website vulnerability scanner
{}---------------------------------------------------------------
{}{}This tool has been created using Python and Termux Emulator.
Have a look at: {}{}{}{}{}
{}{}
This tool is used to analyze website vulnerabilities.
Permission is hereby granted to analyze private property,
not to be used in any illegal manner without the owner's consent.{}
{}---------------------------------------------------------------
""".format(LY,W,auth,LY,W,LM,waktu,LY,W,LM,__version__,N,tgl,LM,
           LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,
           LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,
           LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,LR,W,
           LM,D,W,LB,D,U,__github__,N,D,W,N,LM)

menu = """{}[{}1{}]{}{} Check WP Vuln{}
{}[{}2{}]{}{} Check SQLi Vuln{}
{}[{}3{}]{}{} WebShake / Crawler{}
{}[{}4{}]{}{} Web Analyzer{}
{}[{}5{}]{}{} Port Scanner{}
{}[{}6{}]{}{} DNS Lookup{}
{}[{}7{}]{}{} WHOIS Lookup{}
{}[{}8{}]{}{} Tech Fingerprint{}
{}[{}9{}]{}{} HTTP Header Grab{}
{}[{}0{}]{}{} Settings / Config{}
{}[{}u{}]{}{} Check Update{}
{}[{}x{}]{}{} exit{}
""".format(
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,R,G,LR,D,N,
)
