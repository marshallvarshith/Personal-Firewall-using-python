import logging
import json
from scapy.all import sniff, IP, TCP, UDP, ICMP
from pathlib import Path


def load_rules_from_file(rules_file_path):
    try:
        with open(rules_file_path, 'r') as f:
            return json.load(f)
    except FileNotFoundError:
        logging.error(f"Engine: Rules file not found at {rules_file_path}")
        return []
    except json.JSONDecodeError:
        logging.error(f"Engine: Error decoding JSON from {rules_file_path}")
        return []

def check_match(rule, direction, proto_name, src_ip, dst_ip, src_port, dst_port):
    if rule.get("direction", "ANY").upper() != direction.upper() and rule.get("direction", "ANY").upper() != 'ANY':
        return False
       
    if rule.get("protocol", "ANY").upper() != proto_name.upper() and rule.get("protocol", "ANY").upper() != 'ANY':
        return False
       
    if rule.get("src_ip", "ANY").upper() != 'ANY' and rule.get("src_ip") != src_ip:
        return False
        
    if rule.get("dst_ip", "ANY").upper() != 'ANY' and rule.get("dst_ip") != dst_ip:
        return False
       
    rule_src_port = rule.get("src_port", "ANY")
    if rule_src_port != 'ANY' and rule_src_port != src_port:
        return False
       
    rule_dst_port = rule.get("dst_port", "ANY")
    if rule_dst_port != 'ANY' and rule_dst_port != dst_port:
        return False
           
    return True

def process_packet(packet, rules):
   
    if not packet.haslayer(IP):
        return 

    # Extract Packet Information
    src_ip = packet[IP].src
    dst_ip = packet[IP].dst
    direction = "IN"
   
    proto_name = 'OTHER'
    src_port, dst_port = 'ANY', 'ANY' 

    if packet.haslayer(TCP):
        proto_name = "TCP"
        src_port = packet[TCP].sport
        dst_port = packet[TCP].dport
    elif packet.haslayer(UDP):
        proto_name = "UDP"
        src_port = packet[UDP].sport
        dst_port = packet[UDP].dport
    elif packet.haslayer(ICMP):
        proto_name = "ICMP"
       
       
    # Check Against Rules
    action_taken = False
    for rule in rules:
        if check_match(rule, direction, proto_name, src_ip, dst_ip, src_port, dst_port):
            log_message = (
                f"Rule Match ('{rule.get('name', 'Unnamed Rule')}') -> "
                f"ACTION: {rule.get('action', 'NONE').upper()} | "
                f"DIR: {direction} | PROTO: {proto_name} | "
                f"SRC: {src_ip}:{src_port} -> DST: {dst_ip}:{dst_port}"
            )

            if rule.get('action', '').upper() == 'BLOCK':
                print(f"\033[91m[LOGGED AS BLOCK]\033[0m {log_message}") 
                logging.warning(log_message + " (Action: BLOCK)")
                   
                action_taken = True
                break 
           
            elif rule.get('action', '').upper() == 'ALLOW':
                print(f"[LOGGED AS ALLOW] {log_message}")
                logging.info(log_message + " (Action: ALLOW)")
                action_taken = True
                break

    if not action_taken:
         log_unmatched = (
             f"No Match -> DIR: {direction} | PROTO: {proto_name} | "
             f"SRC: {src_ip}:{src_port} -> DST: {dst_ip}:{dst_port}"
         )
         logging.debug(log_unmatched)


def start_sniffer(rules_file_path_str):
    rules_file_path = Path(rules_file_path_str)
    rules = load_rules_from_file(rules_file_path)
   
    if not rules:
        print("[Engine] No rules loaded or error loading rules. Sniffer not started.")
        logging.error("Engine could not load rules. Sniffer not starting.")
        return

    print(f"[Engine] Loaded {len(rules)} rules. Starting packet capture...")
    logging.info(f"Engine started sniffing with {len(rules)} rules.")
   
    sniff(prn=lambda packet: process_packet(packet, rules), store=0)

