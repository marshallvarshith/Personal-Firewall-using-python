import subprocess
import logging
import json

CHAIN_NAME = "PY_FIREWALL_CLI"

def run_iptables_command(command_args):
    try:
        full_command = ['sudo', 'iptables'] + command_args
        result = subprocess.run(full_command, check=True, capture_output=True, text=True)
        logging.info(f"iptables command successful: {' '.join(full_command)}")
        if result.stdout:
            logging.debug(f"iptables stdout: {result.stdout.strip()}")
        return True
    except subprocess.CalledProcessError as e:
        logging.error(f"iptables command failed: {' '.join(full_command)}\nError: {e.stderr.strip()}")
        print(f"[ERROR] Failed iptables command: {' '.join(e.cmd)}. Error: {e.stderr.strip()}")
        return False
    except FileNotFoundError:
        logging.error("iptables command not found. Is it installed and in PATH?")
        print("[ERROR] iptables command not found.")
        return False

def setup_firewall_chain():
    logging.info(f"Setting up iptables chain: {CHAIN_NAME}")

    run_iptables_command(['-N', CHAIN_NAME])
    check_rule_exists_cmd = ['-C', 'INPUT', '-j', CHAIN_NAME]
    try:
        subprocess.run(['sudo', 'iptables'] + check_rule_exists_cmd, check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
        logging.info(f"Jump rule to {CHAIN_NAME} already exists in INPUT chain.")
    except subprocess.CalledProcessError:
        run_iptables_command(['-I', 'INPUT', '1', '-j', CHAIN_NAME])
        logging.info(f"Inserted jump rule to {CHAIN_NAME} in INPUT chain.")

def apply_block_rules(rules):
    setup_firewall_chain() 
    successful_rules = 0
    for rule in rules:
        if rule.get('action', '').upper() == 'BLOCK':
            rule_args = ['-A', CHAIN_NAME]

            # Translate Rule fields to iptables arguments
            if 'protocol' in rule and rule['protocol'].upper() != 'ANY':
                rule_args.extend(['-p', rule['protocol'].lower()])

            if 'src_ip' in rule and rule['src_ip'].upper() != 'ANY':
                rule_args.extend(['-s', rule['src_ip']])
               
            if 'dst_ip' in rule and rule['dst_ip'].upper() != 'ANY':
                 rule_args.extend(['-d', rule['dst_ip']])

            if 'dst_port' in rule and rule['dst_port'] != 'ANY':
                 if rule.get('protocol', '').upper() in ['TCP', 'UDP']:
                     rule_args.extend(['--dport', str(rule['dst_port'])])
                 else:
                     logging.warning(f"Rule '{rule.get('name', 'Unnamed')}' specifies dst_port but protocol is not TCP/UDP. Port ignored.")
                     
            if 'src_port' in rule and rule['src_port'] != 'ANY':
                 if rule.get('protocol', '').upper() in ['TCP', 'UDP']:
                     rule_args.extend(['--sport', str(rule['src_port'])])
                 else:
                     logging.warning(f"Rule '{rule.get('name', 'Unnamed')}' specifies src_port but protocol is not TCP/UDP. Port ignored.")

            rule_args.append('-j')
            rule_args.append('DROP')
           
            if run_iptables_command(rule_args):
                successful_rules += 1
               
    logging.info(f"Applied {successful_rules} BLOCK rules to iptables chain {CHAIN_NAME}.")
    if successful_rules > 0:
        print(f"Applied {successful_rules} BLOCK rules to the system firewall.")

def flush_rules():
   
    logging.warning(f"Flushing firewall rules and chain: {CHAIN_NAME}")
   
    check_rule_exists_cmd = ['-C', 'INPUT', '-j', CHAIN_NAME]
    try:
        subprocess.run(['sudo', 'iptables'] + check_rule_exists_cmd, check=True, stderr=subprocess.PIPE, stdout=subprocess.PIPE)
       
        run_iptables_command(['-D', 'INPUT', '-j', CHAIN_NAME])
    except subprocess.CalledProcessError:
        logging.info(f"Jump rule to {CHAIN_NAME} not found in INPUT chain. Skipping deletion.")
       
    run_iptables_command(['-F', CHAIN_NAME])

    run_iptables_command(['-X', CHAIN_NAME])
   
    print("System firewall rules flushed.")

