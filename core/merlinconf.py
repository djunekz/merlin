import os, sys, json
from merlincolor import *
from merlinset import *

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'merlin_config.json')

DEFAULT_CONFIG = {
    "timeout"    : 10,
    "user_agent" : "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "max_threads": 5,
    "output_dir" : "./merlin_output",
    "proxy"      : "",
    "verbose"    : False
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
                for key in DEFAULT_CONFIG:
                    if key not in cfg:
                        cfg[key] = DEFAULT_CONFIG[key]
                return cfg
        except (json.JSONDecodeError, IOError):
            print(note + ' Config file corrupted, loading defaults.')
            return DEFAULT_CONFIG.copy()
    return DEFAULT_CONFIG.copy()

def save_config(cfg):
    try:
        with open(CONFIG_FILE, 'w') as f:
            json.dump(cfg, f, indent=4)
        print(note + ' Config saved to ' + Y + CONFIG_FILE + N)
    except IOError as e:
        print(err + ' Failed to save config: ' + str(e))

def show_config(cfg):
    print(LY + '---------------------------------------------------------------' + N)
    print(W  + '  Current Configuration' + N)
    print(LY + '---------------------------------------------------------------' + N)
    for key, val in cfg.items():
        label = (LC + key + N).ljust(30)
        value = LM + str(val) + N if val != "" else DG + "(not set)" + N
        print('  ' + label + ' : ' + value)
    print(LY + '---------------------------------------------------------------' + N)

def edit_config():
    cfg = load_config()
    show_config(cfg)
    print(note + ' Select a key to edit (or ' + R + 'x' + W + ' to go back):')
    keys = list(cfg.keys())
    for i, key in enumerate(keys, 1):
        print('  ' + G + '[' + W + str(i) + G + ']' + LY + ' ' + key + N)
    print('  ' + G + '[' + R + 'x' + G + ']' + LR + ' Back' + N)

    choice = input(LG + '┌──[' + LY + 'termux@localhost' + LG + ']─[' + W + '~/merlin_config' + LG + ']\n└─' + LY + '$ ' + W)

    if choice.lower() == 'x':
        return
    try:
        idx = int(choice) - 1
        if 0 <= idx < len(keys):
            key = keys[idx]
            print(note + ' Current value : ' + LM + str(cfg[key]) + N)
            new_val = input(note + ' Enter new value : ' + W)
            if isinstance(DEFAULT_CONFIG[key], bool):
                cfg[key] = new_val.lower() in ('true', '1', 'yes')
            elif isinstance(DEFAULT_CONFIG[key], int):
                cfg[key] = int(new_val)
            else:
                cfg[key] = new_val
            save_config(cfg)
            print(note + ' ' + LC + key + W + ' updated successfully.')
        else:
            print(err + ' Invalid selection.')
    except (ValueError, IndexError):
        print(err + ' Invalid input.')

config = load_config()

TIMEOUT     = config["timeout"]
USER_AGENT  = config["user_agent"]
MAX_THREADS = config["max_threads"]
OUTPUT_DIR  = config["output_dir"]
PROXY       = config["proxy"]
VERBOSE     = config["verbose"]
