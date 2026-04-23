import os, sys, time
from merlinset import *
from merlincolor import *
from merlinconf import *
from merlinlogo import *
from merlinup import check_update
from merlinconf import edit_config

# Main
def wpvuln():
    try:
       print(note + ' Please enter the target URL')
       print(note + ' Start with ' + Y + 'http://' + W + ' or ' + Y + 'https://')
       takok = input(LY + ' ┌──[' + LG + 'termux@localhost' + LY + ']─[' + W + '~/choose_number/check_wp_vuln' + LY + ']\n └─' + LG + '$ ' + W)
       os.system('python wpvuln.py -u ' + takok)
    except IOError:
       print(err + ' Not Input URL')

def sqli():
    try:
       print(note + ' Please enter the target URL')
       print(note + ' Start with ' + Y + 'http://' + W + ' or ' + Y + 'https://')
       takok = input(LY + ' ┌──[' + LG + 'termux@localhost' + LY + ']─[' + W + '~/choose_number/check_sqli_vuln' + LY + ']\n └─' + LG + '$ ' + W)
       os.system('python websqli.py -u ' + takok)
    except IOError:
       print(err + ' Not Input URL')

def websh():
    try:
       print(note + ' Please enter the target URL')
       print(note + ' Start with ' + Y + 'http://' + W + ' or ' + Y + 'https://')
       takok = input(LY + ' ┌──[' + LG + 'termux@localhost' + LY + ']─[' + W + '~/choose_number/webshake_check' + LY + ']\n └─' + LG + '$ ' + W)
       os.system('python webshake.py -u ' + takok)
    except IOError:
       print(err + ' Not Input URL')

def weban():
    try:
       print(note + ' Please enter the target URL')
       print(note + ' Start with ' + Y + 'http://' + W + ' or ' + Y + 'https://')
       takok = input(LY + ' ┌──[' + LG + 'termux@localhost' + LY + ']─[' + W + '~/choose_number/web_analyzer' + LY + ']\n └─' + LG + '$ ' + W)
       os.system('python webanalyst.py -u ' + takok)
    except IOError:
       print(err + ' Not Input URL')

def main():
    print(logo)
    print(menu)
    tanya = input(LG + '┌──[' + LY + 'termux@localhost' + LG + ']─[' + W + '~/choose_number' + LG + ']\n└─' + LY + '$ ' + W)
    if tanya == '1' or tanya == '01':
       wpvuln()
    elif tanya == '2' or tanya == '02':
       sqli()
    elif tanya == '3' or tanya == '03':
       websh()
    elif tanya == '4' or tanya == '04':
       weban()
    elif tanya == '5' or tanya == '05':
       edit_config()
    elif tanya == '6' or tanya == '06':
       check_update()
    elif tanya == 'x' or tanya == 'X' or tanya == 'exit':
       print(note + ' Close session...done')
       os.system('sleep 1')
       print(note + ' End process...done')
       os.system('sleep 1')
       print(note + ' Clear cache tool...done')
       os.system('sleep 1')
       print(LY + '----- ' + LG + 'Exiting' + LY + ' -----')
       os.system('sleep 2')
       sys.exit()
    else:
       print(err + ' Wrong Command!' + N)
       os.system('sleep 2')
       main()

if __name__ == '__main__':
    main()
