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

menu = """{}[{}1{}]{}{} WP Vulnerability Scan{}
{}[{}2{}]{}{} SQLi / XSS / SSTI Scanner{}
{}[{}3{}]{}{} WebShake / Crawler & Recon{}
{}[{}4{}]{}{} Web Security Analyzer{}
{}[{}5{}]{}{} Port Scanner + Fingerprint{}
{}[{}6{}]{}{} DNS Deep Lookup & Recon{}
{}[{}7{}]{}{} WHOIS Deep Lookup{}
{}[{}8{}]{}{} Technology Fingerprint{}
{}[{}9{}]{}{} HTTP Header Analyzer{}
{}[{}10{}]{}{} SSL/TLS Auditor{}
{}[{}11{}]{}{} Content Discovery{}
{}[{}12{}]{}{} HIBP Credential Checker{}
{}[{}13{}]{}{} Correlation Engine (Risk Chains){}
{}[{}14{}]{}{} Risk Timeline (Drift Tracking){}
{}[{}15{}]{}{} Exposure Story Report{}
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
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,W,G,LY,D,N,
    G,R,G,LR,D,N,
)
