import argparse
import logging
import atexit
import json
from pathlib import Path

from core.engine import start_sniffer
from system.enforcement import apply_block_rules, flush_rules

# Setup Global Paths and Logging
BASE_DIR = Path(__file__).parent
LOG_FILE = BASE_DIR / "logs/firewall.txt"
RULES_FILE = BASE_DIR / "config/rules.json"

# Ensure log and config directories exist
LOG_FILE.parent.mkdir(exist_ok=True)
RULES_FILE.parent.mkdir(exist_ok=True)

logging.basicConfig(
    filename=LOG_FILE,
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)

def load_rules():
    if not RULES_FILE.exists():
        logging.error(f"Rules file not found at {RULES_FILE}")
        print(f"[ERROR] Rules file not found at {RULES_FILE}. Please create it.")
        return []
    with open(RULES_FILE, 'r') as f:
        return json.load(f)

def main():
    parser = argparse.ArgumentParser(description="A simple Python-based CLI firewall.")
    parser.add_argument(
        "action",
        choices=["start", "stop"],
        help="Action to perform: 'start' to activate, 'stop' to deactivate and flush rules."
    )
    args = parser.parse_args()

    if args.action == "start":
        print("Starting firewall...")
        logging.info("Firewall starting up.")

        # This is CRITICAL. It ensures iptables rules are removed on any script exit.
        atexit.register(flush_rules)
       
        print("Performing initial cleanup of old rules...")
        flush_rules()

        # Load and Apply Rules from JSON
        rules = load_rules()
        if not rules:
            print("[ERROR] No rules loaded. Exiting.")
            return
           
        print(f"Applying {len(rules)} rules to the system firewall...")
        apply_block_rules(rules)

        # Start the Sniffing Engine
        print("Sniffing network traffic... Press CTRL+C to stop.")
        try:
            start_sniffer(RULES_FILE)
        except PermissionError:
            print("\n[ERROR] Permission denied. Please run this script with sudo.")
            logging.critical("Permission denied. Script must be run with sudo.")
        except KeyboardInterrupt:
            print("\nShutting down firewall...")
        finally:
            logging.info("Firewall shutdown sequence initiated.")

    elif args.action == "stop":
        print("Stopping firewall and flushing all applied rules...")
        flush_rules()
        logging.info("Firewall stopped and rules flushed manually via 'stop' command.")

if __name__ == "__main__":
    main()
