#!/usr/bin/env bash
# ---------------------------------------------------------------
#  Merlin — Installer
#  Author  : djunekz
#  Tools   : OpenSource
#  GitHub  : https://github.com/djunekz/merlin
# ---------------------------------------------------------------

N='\033[0m'
R='\033[1;91m'
G='\033[1;92m'
Y='\033[1;93m'
C='\033[1;96m'
W='\033[1;97m'
D='\033[2m'

note="${C}[${Y}*${C}]${W}"
ok="${C}[${G}✔${C}]${G}"
err="${C}[${R}!${C}]${R}"
info="${C}[${C}i${C}]${W}"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

_banner() {
    clear
    echo ""
    echo -e "${Y}  ╔══════════════════════════════════════════╗"
    echo -e "  ║                                          ║"
    echo -e "  ║   ${W}M E R L I N  ${D}Installer${N}${Y}                 ║"
    echo -e "  ║   ${D}Website Vulnerability Scanner${N}${Y}          ║"
    echo -e "  ║   ${D}github.com/djunekz/merlin${N}${Y}              ║"
    echo -e "  ║                                          ║"
    echo -e "  ╚══════════════════════════════════════════╝${N}"
    echo ""
}

_spinner() {
    local pid=$1
    local msg=$2
    local frames=('⠋' '⠙' '⠹' '⠸' '⠼' '⠴' '⠦' '⠧' '⠇' '⠏')
    local i=0
    while kill -0 "$pid" 2>/dev/null; do
        printf "\r  ${C}${frames[$i]}${N}  %s" "$msg"
        i=$(( (i+1) % ${#frames[@]} ))
        sleep 0.08
    done
    printf "\r  ${G}✔${N}  %s\n" "$msg"
}

_run() {
    local msg=$1; shift
    "$@" &>/dev/null &
    _spinner $! "$msg"
    wait $!
    return $?
}

_detect_env() {
    if [ -d "/data/data/com.termux" ] || [ -n "$TERMUX_VERSION" ]; then
        echo "termux"
    elif [ -f "/etc/debian_version" ] || command -v apt-get &>/dev/null; then
        echo "debian"
    elif [ -f "/etc/arch-release" ] || command -v pacman &>/dev/null; then
        echo "arch"
    elif [ -f "/etc/fedora-release" ] || command -v dnf &>/dev/null; then
        echo "fedora"
    else
        echo "unknown"
    fi
}

_get_pip() {
    if command -v pip3 &>/dev/null; then echo "pip3"
    elif command -v pip &>/dev/null; then echo "pip"
    else echo ""; fi
}

_get_python() {
    if command -v python3 &>/dev/null; then echo "python3"
    elif command -v python &>/dev/null; then echo "python"
    else echo ""; fi
}

PIP_DEPS=(
    "requests"
    "colorama"
    "beautifulsoup4"
    "lxml"
    "urllib3"
)


install_termux() {
    echo -e "\n${note} Detected environment : ${Y}Termux${N}"
    echo -e "${note} Starting installation...\n"

    _run "Updating package list..."         pkg update -y
    _run "Installing Python..."             pkg install python -y
    _run "Installing git..."                pkg install git -y
    _run "Installing libxml2 (lxml dep)..." pkg install libxml2 -y
    _run "Installing libxslt (lxml dep)..." pkg install libxslt -y
    _run "Upgrading pip..."                 pip install --upgrade pip

    echo ""
    echo -e "${note} Installing Python dependencies..."
    for dep in "${PIP_DEPS[@]}"; do
        _run "  pip: $dep"  pip install "$dep"
    done

    _make_symlink_termux
    _finalize
}

install_linux() {
    echo -e "\n${note} Detected environment : ${Y}Linux (apt)${N}"
    echo -e "${note} Starting installation...\n"

    if [ "$EUID" -ne 0 ]; then
        echo -e "${err} Root privileges required for apt-get. Run with sudo.${N}"
        exit 1
    fi

    _run "Updating package list..."   apt-get update -y
    _run "Installing Python3..."      apt-get install -y python3
    _run "Installing pip3..."         apt-get install -y python3-pip
    _run "Installing git..."          apt-get install -y git
    _run "Installing python3-lxml..."  apt-get install -y python3-lxml
    _run "Upgrading pip..."           pip3 install --upgrade pip

    echo ""
    echo -e "${note} Installing Python dependencies..."
    for dep in "${PIP_DEPS[@]}"; do
        _run "  pip: $dep"  pip3 install "$dep"
    done

    _make_symlink_linux
    _finalize
}

install_arch() {
    echo -e "\n${note} Detected environment : ${Y}Arch Linux${N}"
    echo -e "${note} Starting installation...\n"

    if [ "$EUID" -ne 0 ]; then
        echo -e "${err} Root privileges required. Run with sudo.${N}"
        exit 1
    fi

    _run "Updating package list..."  pacman -Sy --noconfirm
    _run "Installing Python..."      pacman -S --noconfirm python python-pip git
    _run "Upgrading pip..."          pip install --upgrade pip

    echo ""
    echo -e "${note} Installing Python dependencies..."
    for dep in "${PIP_DEPS[@]}"; do
        _run "  pip: $dep"  pip install "$dep"
    done

    _make_symlink_linux
    _finalize
}

install_fedora() {
    echo -e "\n${note} Detected environment : ${Y}Fedora / RHEL${N}"
    echo -e "${note} Starting installation...\n"

    if [ "$EUID" -ne 0 ]; then
        echo -e "${err} Root privileges required. Run with sudo.${N}"
        exit 1
    fi

    _run "Updating package list..."  dnf check-update -y || true
    _run "Installing Python3..."     dnf install -y python3 python3-pip git
    _run "Upgrading pip..."          pip3 install --upgrade pip

    echo ""
    echo -e "${note} Installing Python dependencies..."
    for dep in "${PIP_DEPS[@]}"; do
        _run "  pip: $dep"  pip3 install "$dep"
    done

    _make_symlink_linux
    _finalize
}


_make_symlink_termux() {
    local BIN_DIR="${PREFIX}/bin"
    local TARGET="$SCRIPT_DIR/merlin.sh"
    local LINK="$BIN_DIR/merlin"

    chmod +x "$TARGET"
    echo ""
    if ln -sf "$TARGET" "$LINK" 2>/dev/null; then
        echo -e "${ok} Symlink created : ${Y}$LINK${N} → ${Y}$TARGET${N}"
    else
        echo -e "${err} Could not create symlink at $LINK${N}"
        echo -e "${note} You can run manually: ${Y}bash $TARGET${N}"
    fi
}

_make_symlink_linux() {
    local BIN_DIR="/usr/local/bin"
    local TARGET="$SCRIPT_DIR/merlin.sh"
    local LINK="$BIN_DIR/merlin"

    chmod +x "$TARGET"
    echo ""
    if ln -sf "$TARGET" "$LINK" 2>/dev/null; then
        echo -e "${ok} Symlink created : ${Y}$LINK${N} → ${Y}$TARGET${N}"
    else
        echo -e "${err} Could not create symlink at $LINK (permission denied?)${N}"
        echo -e "${note} Try: ${Y}sudo ln -sf $TARGET $LINK${N}"
        echo -e "${note} Or run manually: ${Y}bash $TARGET${N}"
    fi
}

_finalize() {
    echo ""
    echo -e ""
    echo -e ""
    echo -e "   ${G}Installation complete!${Y}"
    echo -e ""
    echo -e "   Run with: ${W}merlin${Y}"
    echo -e "   Or      : ${W}bash merlin.sh${Y}"
    echo -e ""
    echo ""
}

_menu() {
    _banner
    local ENV
    ENV=$(_detect_env)

    echo -e "${note} Auto-detected environment: ${Y}${ENV}${N}"
    echo ""
    echo -e "  ${C}[${W}1${C}]${Y} Install for Termux"
    echo -e "  ${C}[${W}2${C}]${Y} Install for Linux (apt / Debian / Ubuntu)"
    echo -e "  ${C}[${W}3${C}]${Y} Install for Arch Linux"
    echo -e "  ${C}[${W}4${C}]${Y} Install for Fedora / RHEL"
    echo -e "  ${C}[${R}x${C}]${R} Exit"
    echo ""
    read -rp "$(echo -e "${G}┌──[${Y}installer${G}]─[${W}~/merlin${G}]\n└─${Y}\$ ${W}")" choice

    case "$choice" in
        1) install_termux ;;
        2) install_linux  ;;
        3) install_arch   ;;
        4) install_fedora ;;
        x|X) echo -e "\n${note} Installation cancelled.${N}\n"; exit 0 ;;
        *)
            echo -e "\n${err} Invalid choice.${N}"
            sleep 1
            _menu
            ;;
    esac
}

_menu
