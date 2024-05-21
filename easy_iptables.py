import subprocess
import os
import logging
import psutil
import time
import socket

logging.basicConfig(filename='iptables_manager.log', level=logging.INFO, format='%(asctime)s - %(message)s')


def log_action(action):
    logging.info(action)


def check_sudo():
    if os.geteuid() != 0:
        raise PermissionError("This script must be run as root.")


def manage_iptables(port, action, protocol, chain, ip=None):
    try:
        if action not in ["ACCEPT", "DROP"]:
            raise ValueError("Action must be 'ACCEPT' or 'DROP'")

        if ip:
            command = ["sudo", "iptables", "-A", chain, "-p", protocol, "--dport", str(port), "-s", ip, "-j", action]
        else:
            command = ["sudo", "iptables", "-A", chain, "-p", protocol, "--dport", str(port), "-j", action]

        subprocess.run(command, check=True)
        log_action(
            f"Port {port} with protocol {protocol} in chain {chain} is now set to {action} for IP {ip if ip else 'any'}.")
        print(
            f"Port {port} with protocol {protocol} in chain {chain} is now set to {action} for IP {ip if ip else 'any'}.")

    except subprocess.CalledProcessError as e:
        print(f"Error executing iptables command: {e}")
        log_action(f"Error executing iptables command: {e}")
    except ValueError as e:
        print(e)
        log_action(f"ValueError: {e}")


def delete_iptables_rule_by_number(chain, rule_chain_number):
    try:
        command = ["sudo", "iptables", "-D", chain, str(rule_chain_number)]
        subprocess.run(command, check=True)
        log_action(f"Rule number {rule_chain_number} in chain {chain} is now deleted from iptables.")
        print(f"Rule number {rule_chain_number} in chain {chain} is now deleted from iptables.")
    except subprocess.CalledProcessError as e:
        print(f"Error deleting iptables rule: {e}")
        log_action(f"Error deleting iptables rule: {e}")


def list_iptables_rules(chain=None):
    try:
        if chain:
            command = ["sudo", "iptables", "-L", chain, "-v", "-n", "--line-numbers"]
        else:
            command = ["sudo", "iptables", "-L", "-v", "-n", "--line-numbers"]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        log_action(f"Listed iptables rules for chain {chain if chain else 'all chains'}")
        rules = result.stdout.splitlines()
        print("Rules output:\n", result.stdout)
        return [line for line in rules if line and not line.startswith(('Chain', 'target', 'num'))]
    except subprocess.CalledProcessError as e:
        print(f"Error executing iptables command: {e}")
        log_action(f"Error executing iptables command: {e}")
        return None


def save_and_reload_iptables_rules():
    try:
        command_save = ["sudo", "iptables-save"]
        with open("/etc/iptables/rules.v4", "w") as file:
            subprocess.run(command_save, check=True, stdout=file)

        command_reload = ["sudo", "systemctl", "restart", "netfilter-persistent"]
        subprocess.run(command_reload, check=True)
        print("iptables rules saved and reloaded.")
        log_action("Saved and reloaded iptables rules")
    except subprocess.CalledProcessError as e:
        print(f"Error saving and reloading iptables rules: {e}")
        log_action(f"Error saving and reloading iptables rules: {e}")


def manage_icmp(action, chain):
    try:
        if action not in ["ACCEPT", "DROP"]:
            raise ValueError("Action must be 'ACCEPT' or 'DROP'")

        command = ["sudo", "iptables", "-A", chain, "-p", "icmp", "-j", action]

        subprocess.run(command, check=True)
        print(f"ICMP in chain {chain} is now set to {action}.")
        log_action(f"ICMP in chain {chain} is now set to {action}.")

    except subprocess.CalledProcessError as e:
        print(f"Error executing iptables command: {e}")
        log_action(f"Error executing iptables command: {e}")
    except ValueError as e:
        print(e)
        log_action(f"ValueError: {e}")


def resolve_hostname(hostname):
    try:
        ip = socket.gethostbyname(hostname)
        return ip
    except socket.error as e:
        print(f"Error resolving hostname: {e}")
        return None


def manage_domain_or_ip(action, chain, target):
    ip = resolve_hostname(target) if not target.replace('.', '').isdigit() else target
    if not ip:
        print("Failed to resolve hostname to IP address.")
        return

    try:
        if action not in ["ACCEPT", "DROP"]:
            raise ValueError("Action must be 'ACCEPT' or 'DROP'")

        command = ["sudo", "iptables", "-A", chain, "-s", ip, "-j", action]

        subprocess.run(command, check=True)
        print(f"Target {target} (resolved IP {ip}) in chain {chain} is now set to {action}.")
        log_action(f"Target {target} (resolved IP {ip}) in chain {chain} is now set to {action}.")

    except subprocess.CalledProcessError as e:
        print(f"Error executing iptables command: {e}")
        log_action(f"Error executing iptables command: {e}")
    except ValueError as e:
        print(e)
        log_action(f"ValueError: {e}")


def port_except_ip(port, chain, except_ip, action):
    try:
        if action not in ["ACCEPT", "DROP"]:
            raise ValueError("Action must be 'ACCEPT' or 'DROP'")

        command = ["sudo", "iptables", "-A", chain, "-p", "tcp", "--dport", str(port), "!", "-s", except_ip, "-j",
                   action]
        subprocess.run(command, check=True)
        print(f"Port {port} in chain {chain} is now set to {action} for all except IP {except_ip}.")
        log_action(f"Port {port} in chain {chain} is now set to {action} for all except IP {except_ip}.")
    except subprocess.CalledProcessError as e:
        print(f"Error executing iptables command: {e}")
        log_action(f"Error executing iptables command: {e}")
    except ValueError as e:
        print(e)
        log_action(f"ValueError: {e}")


def print_menu():
    print("\n1. Manage port")
    print("2. Manage ICMP")
    print("3. Manage IP or domain")
    print("4. Block port except for specific IP")
    print("5. View rules")
    print("6. Delete rule")
    print("7. Save and reload rules")
    print("8. Monitor network traffic")
    print("9. Network information")
    print("10. Exit")


def print_action_menu():
    print("\nSelect action:")
    print("1. ACCEPT")
    print("2. DROP")


def print_protocol_menu():
    print("\nSelect protocol:")
    print("1. TCP")
    print("2. UDP")


def print_chain_menu():
    print("\nSelect chain:")
    print("1. INPUT")
    print("2. FORWARD")
    print("3. OUTPUT")


def monitor_network():
    try:
        print("Starting network traffic monitoring. Press Ctrl+C to stop.")
        while True:
            net_io = psutil.net_io_counters()
            print(f"Bytes Sent: {net_io.bytes_sent}, Bytes Received: {net_io.bytes_recv}")
            log_action(f"Bytes Sent: {net_io.bytes_sent}, Bytes Received: {net_io.bytes_recv}")
            time.sleep(1)
    except KeyboardInterrupt:
        print("Network traffic monitoring stopped.")
        log_action("Network traffic monitoring stopped.")


def get_network_info():
    try:
        command = ["ifconfig"]
        result = subprocess.run(command, check=True, capture_output=True, text=True)
        print(result.stdout)
        log_action("Displayed network information using ifconfig")
    except subprocess.CalledProcessError as e:
        print(f"Error executing ifconfig command: {e}")
        log_action(f"Error executing ifconfig command: {e}")


if __name__ == "__main__":
    try:
        check_sudo()
        while True:
            print_menu()
            choice = input("Select an option: ")

            if choice == '1':
                try:
                    port = int(input("Enter port number: "))

                    print_protocol_menu()
                    protocol_choice = input("Select protocol (1 or 2): ")
                    protocol = "tcp" if protocol_choice == '1' else "udp"

                    print_chain_menu()
                    chain_choice = input("Select chain (1, 2, or 3): ")
                    chain = "INPUT" if chain_choice == '1' else "FORWARD" if chain_choice == '2' else "OUTPUT"

                    ip = input("Enter IP address (leave empty for any IP): ").strip() or None

                    print_action_menu()
                    action_choice = input("Select action (1 or 2): ")
                    action = "ACCEPT" if action_choice == '1' else "DROP"

                    manage_iptables(port, action, protocol, chain, ip)
                except ValueError as e:
                    print(e)
            elif choice == '2':
                try:
                    print_chain_menu()
                    chain_choice = input("Select chain (1, 2, or 3): ")
                    chain = "INPUT" if chain_choice == '1' else "FORWARD" if chain_choice == '2' else "OUTPUT"

                    print_action_menu()
                    action_choice = input("Select action (1 or 2): ")
                    action = "ACCEPT" if action_choice == '1' else "DROP"

                    manage_icmp(action, chain)
                except ValueError as e:
                    print(e)
            elif choice == '3':
                try:
                    target = input("Enter IP address or domain name to block/allow: ").strip()
                    if not target:
                        raise ValueError("IP address or domain name cannot be empty")

                    print_chain_menu()
                    chain_choice = input("Select chain (1, 2, or 3): ")
                    chain = "INPUT" if chain_choice == '1' else "FORWARD" if chain_choice == '2' else "OUTPUT"

                    print_action_menu()
                    action_choice = input("Select action (1 or 2): ")
                    action = "ACCEPT" if action_choice == '1' else "DROP"

                    manage_domain_or_ip(action, chain, target)
                except ValueError as e:
                    print(e)
            elif choice == '4':
                try:
                    port = int(input("Enter port number to block/allow: "))
                    except_ip = input("Enter IP address to allow: ").strip()
                    if not except_ip:
                        raise ValueError("IP address cannot be empty")

                    print_chain_menu()
                    chain_choice = input("Select chain (1, 2, or 3): ")
                    chain = "INPUT" if chain_choice == '1' else "FORWARD" if chain_choice == '2' else "OUTPUT"

                    print_action_menu()
                    action_choice = input("Select action (1 or 2): ")
                    action = "ACCEPT" if action_choice == '1' else "DROP"

                    port_except_ip(port, chain, except_ip, action)
                except ValueError as e:
                    print(e)
            elif choice == '5':
                try:
                    print_chain_menu()
                    chain_choice = input("Select chain (1, 2, or 3): ")
                    chain = "INPUT" if chain_choice == '1' else "FORWARD" if chain_choice == '2' else "OUTPUT"
                    rules = list_iptables_rules(chain)
                    if rules:
                        print("\n".join(rules))  # Выводим правила на экран
                    else:
                        print("No rules found.")
                except ValueError as e:
                    print(e)
            elif choice == '6':
                try:
                    print_chain_menu()
                    chain_choice = input("Select chain (1, 2, or 3): ")
                    chain = "INPUT" if chain_choice == '1' else "FORWARD" if chain_choice == '2' else "OUTPUT"

                    rules = list_iptables_rules(chain)
                    if rules and len(rules) > 0:
                        print("Available rules:")
                        for idx, rule in enumerate(rules):
                            print(f"{idx + 1}. {rule}")
                        rule_number = int(input("Enter rule number to delete: "))
                        rule_chain_number = rules[rule_number - 1].split()[0]
                        delete_iptables_rule_by_number(chain, rule_chain_number)
                    else:
                        print("No rules to delete.")
                except (ValueError, IndexError) as e:
                    print(f"Invalid rule number: {e}")
            elif choice == '7':
                save_and_reload_iptables_rules()
            elif choice == '8':
                monitor_network()
            elif choice == '9':
                get_network_info()
            elif choice == '10':
                print("Exiting program.")
                break
            else:
                print("Invalid choice, please try again.")
    except PermissionError as e:
        print(e)
    except KeyboardInterrupt:
        print("Exiting program.")
        log_action("Program stopped by user.")


