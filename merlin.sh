#!/usr/bin/env bash
# ---------------------------------------------------------------
#  Merlin — Website Vulnerability Scanner
#  Author  : djunekz
#  Tools   : OpenSource
#  GitHub  : https://github.com/djunekz/merlin
# ---------------------------------------------------------------

N='\033[0m'
R='\033[1;91m'
G='\033[1;92m'
Y='\033[1;93m'
B='\033[1;94m'
M='\033[1;95m'
C='\033[1;96m'
W='\033[1;97m'
D='\033[2m'

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
CORE_DIR="$SCRIPT_DIR/core"

if [ ! -d "$CORE_DIR" ]; then
    echo -e "${R}[!]${N} core/ directory not found. Please reinstall merlin."
    exit 1
fi

if ! command -v python3 &>/dev/null && ! command -v python &>/dev/null; then
    echo -e "${R}[!]${N} Python not found. Run ${Y}./install.sh${N} first."
    exit 1
fi

PYTHON=$(command -v python3 || command -v python)

trap _exit_handler INT

_exit_handler() {
    echo ""
    _goodbye
    exit 0
}

_spinner() {
    local pid=$1
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${C}${frames[$i]}${N}  %s" "$2"
        i=$(( (i+1) % ${#frames[@]} ))
        sleep 0.08
    done
    printf "\r  ${G}✔${N}  %s\n" "$2"
}

_loading() {
    clear
    echo ""
    echo -e "${Y}  ══════════════════════════════════════════"
    echo -e ""
    echo -e "   ${W}M E R L I N ${Y}• ${G}${D}https://github.com/djunekz${W}"
    echo -e "   ${D}Website Vulnerability Scanner${N}${Y}"
    echo -e ""
    echo -e "  ══════════════════════════════════════════${N}"
    echo ""

    sleep 0.3 &
    _spinner $! "Initializing environment..."

    sleep 0.4 &
    _spinner $! "Loading modules..."

    sleep 0.3 &
    _spinner $! "Checking dependencies..."

    sleep 0.5 &
    _spinner $! "Setting up scanner engine..."

    echo ""
    echo -e "  ${G}[✔]${N} Merlin is ready. Launching..."
    echo ""
    sleep 0.6
    clear
}

_goodbye() {
    echo ""
    echo -e "${D}"
    echo -e ""
    echo -e "   ${W}Thanks for using Merlin!${W}"
    echo -e "   ${W}Stay ethical. Hack responsibly."
    echo -e ""
    echo -e "   ${G}https://github.com/djunekz/merlin"
    echo -e ""
    echo -e "${N}"
    echo ""

    local steps=("Closing session" "Terminating processes" "Clearing cache" "Goodbye")
    for step in "${steps[@]}"; do
        sleep 0.4 &
        _spinner $! "$step..."
    done
    echo ""
}

_loading
cd "$CORE_DIR" || exit 1
"$PYTHON" merlin.py
EXIT_CODE=$?

if [ "$EXIT_CODE" -ne 0 ]; then
    echo -e "\n${R}[!]${N} Merlin exited with error code ${EXIT_CODE}."
fi
