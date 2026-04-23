import os, sys, subprocess
from merlinset import *
from merlincolor import *

REPO_URL    = "https://github.com/djunekz/merlin"
REPO_CLONE  = "https://github.com/djunekz/merlin.git"
CURRENT_VER = "1.0.0"

def check_git():
    try:
        subprocess.run(['git', '--version'], capture_output=True, check=True)
        return True
    except (subprocess.CalledProcessError, FileNotFoundError):
        return False

def get_remote_version():
    try:
        result = subprocess.run(
            ['git', 'ls-remote', '--tags', REPO_CLONE],
            capture_output=True, text=True, timeout=10
        )
        lines = result.stdout.strip().splitlines()
        tags = []
        for line in lines:
            parts = line.split('\t')
            if len(parts) == 2 and 'refs/tags/' in parts[1] and '^{}' not in parts[1]:
                tag = parts[1].replace('refs/tags/', '').strip()
                tags.append(tag)
        if tags:
            return tags[-1]
        return None
    except Exception:
        return None

def do_update():
    if not check_git():
        print(err + ' Git is not installed. Install it first with:')
        print('  ' + Y + 'pkg install git' + N)
        return

    if os.path.exists('.git'):
        print(note + ' Downloading update from ' + LB + REPO_URL + N + '...')
        try:
            result = subprocess.run(
                ['git', 'pull', 'origin', 'main'],
                capture_output=True, text=True, timeout=30
            )
            if result.returncode == 0:
                print(sukses + ' Update successful!')
                print('  ' + DG + result.stdout.strip() + N)
            else:
                print(err + ' Update failed:')
                print('  ' + R + result.stderr.strip() + N)
        except subprocess.TimeoutExpired:
            print(err + ' Connection timed out. Please try again later.')
        except Exception as e:
            print(err + ' Error: ' + str(e))
    else:
        print(warning + ' This folder is not a git repository.')
        print(note + ' Re-clone the repo with:')
        print('  ' + Y + 'git clone ' + REPO_CLONE + N)

def check_update():
    print(LY + '---------------------------------------------------------------' + N)
    print(W  + '  Update Checker' + N)
    print(LY + '---------------------------------------------------------------' + N)
    print(note + ' Current version : ' + LM + CURRENT_VER + N)
    print(note + ' Checking for latest version...')

    if not check_git():
        print(err + ' Git not found, cannot check for updates.')
        print(note + ' Install git: ' + Y + 'pkg install git' + N)
        return

    remote = get_remote_version()
    if remote is None:
        print(warning + ' Unable to connect to GitHub. Check your internet connection.')
        return

    print(note + ' Latest version  : ' + LM + remote + N)
    print(LY + '---------------------------------------------------------------' + N)

    if remote == CURRENT_VER:
        print(sukses + ' Tool is already ' + LG + 'up-to-date' + N + '!')
    else:
        print(info + ' New version available: ' + LG + remote + N)
        print(note + ' Update now? ' + G + '[y/n]' + N)
        jawab = input(LG + '┌──[' + LY + 'termux@localhost' + LG + ']─[' + W + '~/merlin_update' + LG + ']\n└─' + LY + '$ ' + W)
        if jawab.lower() in ('y', 'yes'):
            do_update()
        else:
            print(note + ' Update cancelled.')

    print(LY + '---------------------------------------------------------------' + N)
