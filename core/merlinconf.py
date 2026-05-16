import os, sys, json
from merlincolor import *
from merlinset import *

CONFIG_FILE = os.path.join(os.path.dirname(__file__), 'merlin_config.json')

DEFAULT_CONFIG = {
    "timeout"          : 6,
    "user_agent"       : "Mozilla/5.0 (Linux; Android 10) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.120 Mobile Safari/537.36",
    "max_threads"      : 5,
    "output_dir"       : "./merlin_output",
    "proxy"            : "",
    "verbose"          : False,
    "crawl_depth"      : 2,
    "follow_redirects" : True,
    "sqli_deep_scan"   : False,
    "xss_deep_scan"    : False,
    "port_range"       : "1-1024",
    "dns_resolvers"    : "8.8.8.8,1.1.1.1",
    "save_reports"     : True,
    "report_format"    : "json",
    "rate_limit_delay" : 0.5,
    "max_retries"      : 3,
    "verify_ssl"       : True,
}

def load_config():
    if os.path.exists(CONFIG_FILE):
        try:
            with open(CONFIG_FILE, 'r') as f:
                cfg = json.load(f)
                changed = False
                for key in DEFAULT_CONFIG:
                    if key not in cfg:
                        cfg[key] = DEFAULT_CONFIG[key]
                        changed = True
                if changed:
                    save_config(cfg)
                return cfg
        except (json.JSONDecodeError, IOError):
            print(note + ' Config file corrupted, loading defaults.')
            cfg = DEFAULT_CONFIG.copy()
            save_config(cfg)
            return cfg
    cfg = DEFAULT_CONFIG.copy()
    save_config(cfg)
    return cfg

def save_config(cfg):
    try:
        os.makedirs(os.path.dirname(CONFIG_FILE), exist_ok=True)
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
        label = (LC + key + N).ljust(38)
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
    print('  ' + G + '[' + R + 'r' + G + ']' + LY + ' Reset to defaults' + N)

    try:
        choice = input(LG + '┌──[' + LY + 'termux@localhost' + LG + ']─[' + W + '~/merlin_config' + LG + ']\n└─' + LY + '$ ' + W)
    except (EOFError, KeyboardInterrupt):
        return

    if choice.lower() == 'x':
        return

    if choice.lower() == 'r':
        confirm = input(note + ' Reset ALL config to defaults? ' + R + '[y/N]' + W + ' ')
        if confirm.lower() in ('y', 'yes'):
            save_config(DEFAULT_CONFIG.copy())
            print(note + ' Config reset to defaults.')
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
                try:
                    cfg[key] = int(new_val)
                except ValueError:
                    print(err + ' Invalid integer value.')
                    return
            elif isinstance(DEFAULT_CONFIG[key], float):
                try:
                    cfg[key] = float(new_val)
                except ValueError:
                    print(err + ' Invalid float value.')
                    return
            else:
                cfg[key] = new_val
            save_config(cfg)
            print(note + ' ' + LC + key + W + ' updated successfully.')
        else:
            print(err + ' Invalid selection.')
    except (ValueError, IndexError):
        print(err + ' Invalid input.')

config = load_config()

TIMEOUT           = config["timeout"]
TIMEOUT_TUPLE     = (config["timeout"], config["timeout"] * 2)
USER_AGENT        = config["user_agent"]
MAX_THREADS       = config["max_threads"]
OUTPUT_DIR        = config["output_dir"]
PROXY             = config["proxy"]
VERBOSE           = config["verbose"]
CRAWL_DEPTH       = config["crawl_depth"]
FOLLOW_REDIRECTS  = config["follow_redirects"]
SQLI_DEEP_SCAN    = config["sqli_deep_scan"]
XSS_DEEP_SCAN     = config["xss_deep_scan"]
PORT_RANGE        = config["port_range"]
DNS_RESOLVERS     = config["dns_resolvers"]
SAVE_REPORTS      = config["save_reports"]
REPORT_FORMAT     = config["report_format"]
RATE_LIMIT_DELAY  = config["rate_limit_delay"]
MAX_RETRIES       = config["max_retries"]
VERIFY_SSL        = config["verify_ssl"]
