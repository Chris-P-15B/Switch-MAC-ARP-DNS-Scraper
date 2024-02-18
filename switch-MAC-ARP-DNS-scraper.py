#!/usr/bin/env python3

"""
Copyright (c) 2023 - 2024, Chris Perkins
Licence: BSD 3-Clause

Connects to switches in parallel, retrieves interface status & details (MAC address, IP address & hostname)
 of connected hosts. Then tabulates this data by MAC address & outputs to a CSV file.

 v1.0 - Initial public release.
"""

import sys
import re
import socket
import csv
import base64
from getpass import getpass
from netmiko.exceptions import (
    NetMikoTimeoutException,
    NetMikoAuthenticationException,
)
from paramiko.ssh_exception import SSHException
from ssh_autodetect import SSHDetect
from netmiko.ssh_dispatcher import ConnectHandler
from threading import Thread
from pprint import pprint


def guess_device_type(remote_device):
    """Auto-detect device type"""
    try:
        guesser = SSHDetect(**remote_device)
        best_match = guesser.autodetect()
    except NetMikoAuthenticationException:
        print(
            f"Failed to execute CLI on {remote_device['host']} due to incorrect credentials."
        )
        return None
    except (NetMikoTimeoutException, SSHException):
        print(
            f"Failed to execute CLI on {remote_device['host']} due to timeout or SSH not enabled."
        )
        return None
    except ValueError:
        print(
            f"Unsupported platform {remote_device['host']}, {remote_device['device_type']}."
        )
        return None
    else:
        return best_match


def dns_reverse_lookup(ip_address, dns_table):
    """DNS reverse lookup, update dictionary with result"""
    try:
        reversed_dns = socket.gethostbyaddr(ip_address)
    except socket.herror:
        # No DNS record, don't store in dictionary
        pass
    else:
        dns_table[ip_address] = reversed_dns[0]


def validate_mac_address(mac_address):
    """Validate MAC address & return it in standard format"""
    mac_address = mac_address.lower()
    for digit in mac_address:
        if digit in ".:-":
            mac_address = mac_address.replace(digit, "")
    if len(mac_address) != 12:
        return None
    for digit in mac_address:
        if digit not in [
            "0",
            "1",
            "2",
            "3",
            "4",
            "5",
            "6",
            "7",
            "8",
            "9",
            "a",
            "b",
            "c",
            "d",
            "e",
            "f",
        ]:
            return None
    mac_address = mac_address[0:4] + "." + mac_address[4:8] + "." + mac_address[8:12]
    return mac_address


def parse_arista(best_match, device, interface_list):
    """Handle Arista devices"""
    # Find column heading line & then parse VRF names in lines below
    VRF_names = []
    cli_output = device.send_command("show vrf")
    cntr = 0
    for cli_line in cli_output.splitlines():
        cntr += 1
        if "-------------" in cli_line:
            break
    for cli_line in cli_output.splitlines()[cntr:]:
        columns = cli_line.split()
        if len(columns) >= 5:
            VRF_names.append(columns[0])
    # Parse ARP table into dictionary to refer back to
    arp_table = {}
    for VRF in VRF_names:
        cli_output = device.send_command(f"show ip arp vrf {VRF}")
        for cli_line in cli_output.splitlines():
            arp_entry = re.search(
                r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                cli_line,
            )
            if arp_entry:
                ip_address = arp_entry.group(1)
                mac_address = validate_mac_address(arp_entry.group(2))
                arp_table[mac_address] = ip_address

    # Multi-threaded DNS reverse lookup, store in dictionary to refer back to
    dns_table = {}
    dns_threads = []
    for ip_address in arp_table.values():
        dns_worker = Thread(target=dns_reverse_lookup, args=(ip_address, dns_table))
        dns_worker.start()
        dns_threads.append(dns_worker)
    for dns_worker in dns_threads:
        dns_worker.join()

    # Grab interface status
    cli_output = device.send_command("show interface status")
    cli_output = cli_output.splitlines()
    # Find offsets for column headings in the output
    for cli_line in cli_output:
        PORT_COLUMN = cli_line.find("Port")
        NAME_COLUMN = cli_line.find("Name")
        STATUS_COLUMN = cli_line.find("Status")
        VLAN_COLUMN = cli_line.find("Vlan")
        DUPLEX_COLUMN = cli_line.find("Duplex")
        SPEED_COLUMN = cli_line.find("Speed")
        TYPE_COLUMN = cli_line.find("Type")
        FLAGS_COLUMN = cli_line.find("Flags")

        if (
            PORT_COLUMN
            == NAME_COLUMN
            == STATUS_COLUMN
            == VLAN_COLUMN
            == DUPLEX_COLUMN
            == SPEED_COLUMN
            == TYPE_COLUMN
            == FLAGS_COLUMN
            == -1
        ):
            continue
        else:
            break

    # Parse output & retrieve information for interfaces that are connected
    for cli_line in cli_output:
        try:
            interface_dict = {
                "interface": cli_line[PORT_COLUMN:NAME_COLUMN].strip(),
                "description": cli_line[NAME_COLUMN:STATUS_COLUMN].strip(),
                "status": cli_line[STATUS_COLUMN:VLAN_COLUMN].strip(),
                "VLAN": cli_line[VLAN_COLUMN:DUPLEX_COLUMN].strip(),
                "duplex": cli_line[DUPLEX_COLUMN:SPEED_COLUMN].strip(),
                "speed": cli_line[SPEED_COLUMN:TYPE_COLUMN].strip(),
                "type": cli_line[TYPE_COLUMN:FLAGS_COLUMN].strip(),
            }
            if interface_dict["VLAN"].isdigit():
                interface_dict["VLAN"] = "access " + interface_dict["VLAN"]
            # Filter for interfaces that are connected
            if interface_dict["status"] and interface_dict["status"] in "connected":
                cli_output2 = device.send_command(
                    f"show mac address-table interface {interface_dict['interface']}"
                )
                cli_output2 = cli_output2.splitlines()
                connected_hosts = []
                for mac_line in cli_output2:
                    mac_address = re.search(
                        r"(\d+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                        mac_line,
                    )
                    if mac_address:
                        vlan = mac_address.group(1)
                        mac_address = validate_mac_address(mac_address.group(2))
                        # Exclude broadcast MAC
                        if mac_address != "ffff.ffff.ffff":
                            # Lookup IP address & hostname in stored tables
                            if arp_table.get(mac_address, None):
                                ip_address = arp_table[mac_address]
                                if dns_table.get(ip_address, None):
                                    hostname = dns_table[ip_address]
                                else:
                                    hostname = ""
                            else:
                                ip_address = ""
                                hostname = ""
                            connected_hosts.append(
                                {
                                    "vlan": vlan,
                                    "mac": mac_address,
                                    "ip": ip_address,
                                    "dns": hostname,
                                }
                            )
                interface_dict["hosts"] = connected_hosts
                # Grab full description from show interface
                cli_output3 = device.send_command(
                    f"show interface {interface_dict['interface']}"
                )
                int_description = re.search(r"Description: (.+)\n", cli_output3)
                int_description = (
                    int_description.group(1).rstrip() if int_description else ""
                )
                interface_dict["description"] = int_description
                del interface_dict["status"]
                interface_list.append(interface_dict)
        except IndexError:
            continue


def parse_aruba(best_match, device, interface_list):
    """Handle Aruba CX devices"""
    # Parse VRF names
    VRF_names = []
    cli_output = device.send_command("show vrf")
    for cli_line in cli_output.splitlines():
        columns = re.search(r"VRF Name\s+: (.+)", cli_line)
        if columns:
            VRF_names.append(columns.group(1))
    # Parse ARP table into dictionary to refer back to
    arp_table = {}
    for VRF in VRF_names:
        cli_output = device.send_command(f"show arp vrf {VRF}")
        for cli_line in cli_output.splitlines():
            arp_entry = re.search(
                r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})\s",
                cli_line,
            )
            if arp_entry:
                ip_address = arp_entry.group(1)
                mac_address = validate_mac_address(arp_entry.group(2))
                arp_table[mac_address] = ip_address

    # Multi-threaded DNS reverse lookup, store in dictionary to refer back to
    dns_table = {}
    dns_threads = []
    for ip_address in arp_table.values():
        dns_worker = Thread(target=dns_reverse_lookup, args=(ip_address, dns_table))
        dns_worker.start()
        dns_threads.append(dns_worker)
    for dns_worker in dns_threads:
        dns_worker.join()

    # Grab interface status
    cli_output = device.send_command("show interface brief")
    cli_output = cli_output.splitlines()
    # Find offsets for column headings in the output
    for cli_line in cli_output:
        PORT_COLUMN = cli_line.find("Port")
        VLAN_COLUMN = cli_line.find("Native")
        MODE_COLUMN = cli_line.find("Mode")
        TYPE_COLUMN = cli_line.find("Type")
        ENABLED_COLUMN = cli_line.find("Enabled")
        STATUS_COLUMN = cli_line.find("Status")
        REASON_COLUMN = cli_line.find("Reason")
        SPEED_COLUMN = cli_line.find("Speed")
        NAME_COLUMN = cli_line.find("Description")

        if (
            PORT_COLUMN
            == VLAN_COLUMN
            == MODE_COLUMN
            == TYPE_COLUMN
            == ENABLED_COLUMN
            == STATUS_COLUMN
            == REASON_COLUMN
            == SPEED_COLUMN
            == NAME_COLUMN
            == -1
        ):
            continue
        else:
            break

    # Parse output & retrieve information for interfaces that are connected
    for cli_line in cli_output:
        try:
            interface_dict = {
                "interface": cli_line[PORT_COLUMN:VLAN_COLUMN].strip(),
                "description": cli_line[NAME_COLUMN:].strip(),
                "status": cli_line[STATUS_COLUMN:REASON_COLUMN].strip(),
                "VLAN": cli_line[MODE_COLUMN:TYPE_COLUMN].strip()
                + " "
                + cli_line[VLAN_COLUMN:MODE_COLUMN].strip(),
                "duplex": "",
                "speed": cli_line[SPEED_COLUMN:NAME_COLUMN].strip(),
                "type": cli_line[TYPE_COLUMN:ENABLED_COLUMN].strip(),
            }
            # Filter for interfaces that are connected
            if interface_dict["status"] and interface_dict["status"] in "up":
                cli_output2 = device.send_command(
                    f"show mac-address-table port {interface_dict['interface']}"
                )
                cli_output2 = cli_output2.splitlines()
                connected_hosts = []
                for mac_line in cli_output2:
                    mac_address = re.search(
                        r"([0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2}:[0-9a-f]{2})\s+(\d+)\s+",
                        mac_line,
                    )
                    if mac_address:
                        vlan = mac_address.group(2)
                        mac_address = validate_mac_address(mac_address.group(1))
                        # Exclude broadcast MAC
                        if mac_address != "ffff.ffff.ffff":
                            # Lookup IP address & hostname in stored tables
                            if arp_table.get(mac_address, None):
                                ip_address = arp_table[mac_address]
                                if dns_table.get(ip_address, None):
                                    hostname = dns_table[ip_address]
                                else:
                                    hostname = ""
                            else:
                                ip_address = ""
                                hostname = ""
                            connected_hosts.append(
                                {
                                    "vlan": vlan,
                                    "mac": mac_address,
                                    "ip": ip_address,
                                    "dns": hostname,
                                }
                            )
                interface_dict["hosts"] = connected_hosts
                # Grab full description from show interface
                cli_output3 = device.send_command(
                    f"show interface {interface_dict['interface']}"
                )
                int_description = re.search(r"Description: (.+)\n", cli_output3)
                int_description = (
                    int_description.group(1).rstrip() if int_description else ""
                )
                interface_dict["description"] = int_description
                del interface_dict["status"]
                interface_list.append(interface_dict)
        except IndexError:
            continue


def parse_cisco(best_match, device, interface_list):
    """Handle Cisco IOS, IOS XE & NX-OS devices"""
    # Find column heading line & then parse VRF names in lines below
    VRF_names = []
    cli_output = device.send_command("show vrf")
    cntr = 0
    for cli_line in cli_output.splitlines():
        cntr += 1
        if "VRF-Name" in cli_line or "Name" in cli_line:
            break
    for cli_line in cli_output.splitlines()[cntr:]:
        columns = cli_line.split()
        if len(columns) >= 4:
            VRF_names.append(columns[0])
    # Parse ARP table into dictionary to refer back to
    arp_table = {}
    # IOS syntax for the default VRF is different from other VRFs
    if best_match == "cisco_ios" or best_match == "cisco_xe":
        cli_output = device.send_command("show ip arp")
        for cli_line in cli_output.splitlines():
            arp_entry = re.search(
                r"^Internet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                cli_line,
            )
            if arp_entry:
                ip_address = arp_entry.group(1)
                mac_address = validate_mac_address(arp_entry.group(2))
                arp_table[mac_address] = ip_address
    for VRF in VRF_names:
        cli_output = device.send_command(f"show ip arp vrf {VRF}")
        for cli_line in cli_output.splitlines():
            if best_match == "cisco_nxos":
                arp_entry = re.search(
                    r"^(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                    cli_line,
                )
            else:
                arp_entry = re.search(
                    r"^Internet\s+(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\s+.+\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                    cli_line,
                )
            if arp_entry:
                ip_address = arp_entry.group(1)
                mac_address = validate_mac_address(arp_entry.group(2))
                arp_table[mac_address] = ip_address

    # Multi-threaded DNS reverse lookup, store in dictionary to refer back to
    dns_table = {}
    dns_threads = []
    for ip_address in arp_table.values():
        dns_worker = Thread(target=dns_reverse_lookup, args=(ip_address, dns_table))
        dns_worker.start()
        dns_threads.append(dns_worker)
    for dns_worker in dns_threads:
        dns_worker.join()

    # Grab interface status
    cli_output = device.send_command("show interface status")
    cli_output = cli_output.splitlines()
    # Find offsets for column headings in the output
    for cli_line in cli_output:
        PORT_COLUMN = cli_line.find("Port")
        NAME_COLUMN = cli_line.find("Name")
        STATUS_COLUMN = cli_line.find("Status")
        VLAN_COLUMN = cli_line.find("Vlan")
        DUPLEX_COLUMN = cli_line.find("Duplex")
        SPEED_COLUMN = cli_line.find("Speed")
        TYPE_COLUMN = cli_line.find("Type")

        if (
            PORT_COLUMN
            == NAME_COLUMN
            == STATUS_COLUMN
            == VLAN_COLUMN
            == DUPLEX_COLUMN
            == SPEED_COLUMN
            == TYPE_COLUMN
            == -1
        ):
            continue
        else:
            break

    # Parse output & retrieve information for interfaces that are connected
    for cli_line in cli_output:
        try:
            interface_dict = {
                "interface": cli_line[PORT_COLUMN:NAME_COLUMN],
                "description": cli_line[NAME_COLUMN:STATUS_COLUMN].strip(),
                "status": cli_line[STATUS_COLUMN:VLAN_COLUMN].strip(),
                "VLAN": cli_line[VLAN_COLUMN:DUPLEX_COLUMN].strip(),
                "duplex": cli_line[DUPLEX_COLUMN : SPEED_COLUMN - 1].strip(),
                "speed": cli_line[SPEED_COLUMN - 1 : TYPE_COLUMN].strip(),
                "type": cli_line[TYPE_COLUMN:].strip(),
            }
            interface_dict["interface"] = interface_dict["interface"][
                : interface_dict["interface"].rfind(" ")
            ].strip()
            if interface_dict["VLAN"].isdigit():
                interface_dict["VLAN"] = "access " + interface_dict["VLAN"]
            # Filter for interfaces that are connected
            if interface_dict["status"] and interface_dict["status"] in "connected":
                cli_output2 = device.send_command(
                    f"show mac address-table interface {interface_dict['interface']}"
                )
                cli_output2 = cli_output2.splitlines()
                connected_hosts = []
                for mac_line in cli_output2:
                    mac_address = re.search(
                        r"([\w\-\/]+)\s+([0-9a-f]{4}\.[0-9a-f]{4}\.[0-9a-f]{4})\s",
                        mac_line,
                    )
                    if mac_address:
                        vlan = mac_address.group(1)
                        mac_address = validate_mac_address(mac_address.group(2))
                        # Exclude broadcast MAC
                        if mac_address != "ffff.ffff.ffff":
                            # Lookup IP address & hostname in stored tables
                            if arp_table.get(mac_address, None):
                                ip_address = arp_table[mac_address]
                                if dns_table.get(ip_address, None):
                                    hostname = dns_table[ip_address]
                                else:
                                    hostname = ""
                            else:
                                ip_address = ""
                                hostname = ""
                            connected_hosts.append(
                                {
                                    "vlan": vlan,
                                    "mac": mac_address,
                                    "ip": ip_address,
                                    "dns": hostname,
                                }
                            )
                interface_dict["hosts"] = connected_hosts
                # Grab full description from show interface
                cli_output3 = device.send_command(
                    f"show interface {interface_dict['interface']}"
                )
                int_description = re.search(r"Description: (.+)\n", cli_output3)
                int_description = (
                    int_description.group(1).rstrip() if int_description else ""
                )
                interface_dict["description"] = int_description
                del interface_dict["status"]
                interface_list.append(interface_dict)
        except IndexError:
            continue


def scrape_switch_details(
    target_device, target_username, target_password, output_text, results_dict
):
    """Connect to a switch & parse outputs to retrieve connected interface's MAC, ARP & hostname details"""
    output_messages = ""
    try:
        # Auto-detect device type & establish correct SSH connection
        best_match = guess_device_type(
            {
                "device_type": "autodetect",
                "host": target_device,
                "username": target_username,
                "password": target_password,
                "read_timeout_override": 60,
                "fast_cli": False,
            }
        )
        if best_match is None:
            output_messages += f"Error: Unknown platform for {target_device}.\n"
            output_text.append(output_messages)
            return

        output_messages += (
            f"\nConnecting to device: {target_device}, type: {best_match}\n"
        )
        device = ConnectHandler(
            device_type=best_match,
            host=target_device,
            username=target_username,
            password=target_password,
            secret=target_password,
            read_timeout_override=25,
            fast_cli=False,
            global_cmd_verify=False,
        )
    except NetMikoAuthenticationException:
        output_messages += (
            f"Failed to execute CLI on {target_device} due to incorrect credentials.\n"
        )
        output_text.append(output_messages)
        return
    except (NetMikoTimeoutException, SSHException):
        output_messages += f"Failed to execute CLI on {target_device} due to timeout or SSH not enabled.\n"
        output_text.append(output_messages)
        return
    except ValueError:
        output_messages += f"Unsupported platform {target_device}, {best_match}.\n"
        output_text.append(output_messages)
        return
    else:
        device.enable()
        interface_list = []

        # Arista EOS
        if best_match == "arista_eos":
            parse_arista(best_match, device, interface_list)
            device.disconnect()

        # Cisco IOS, IOS XE & NX-OS
        elif (
            best_match == "cisco_ios"
            or best_match == "cisco_xe"
            or best_match == "cisco_nxos"
        ):
            parse_cisco(best_match, device, interface_list)
            device.disconnect()

        # Juniper JunOs
        elif best_match == "juniper" or best_match == "juniper_junos":
            # Do something
            device.disconnect()

        # Aruba CX
        elif best_match == "aruba_osswitch":
            parse_aruba(best_match, device, interface_list)
            device.disconnect()

        # Unsupported, disconnect
        else:
            output_messages += f"Unsupported platform {target_device}, {best_match}.\n"
            output_text.append(output_messages)
            device.disconnect()
            return

        # Store the connected interface details for display later + build MAC address keyed dictionary of interfaces
        output_messages += f"\n{target_device} Interface & Connected Host List:\n\n"
        for interface in interface_list:
            hosts = ""
            for host in interface["hosts"]:
                if host["mac"] not in results_dict:
                    results_dict[host["mac"]] = {"ip": [], "dns": [], "ports": []}
                hosts += f"VLAN {host['vlan']} {host['mac']}"
                if host["ip"]:
                    hosts += f" {host['ip']}"
                    if host["ip"] not in results_dict[host["mac"]]["ip"]:
                        results_dict[host["mac"]]["ip"].append(host["ip"])
                if host["dns"]:
                    hosts += f" {host['dns']}"
                    if host["dns"] not in results_dict[host["mac"]]["dns"]:
                        results_dict[host["mac"]]["dns"].append(host["dns"])
                hosts += ", "
                results_dict[host["mac"]]["ports"].append(
                    {
                        "switch": target_device,
                        "interface": interface["interface"],
                        "description": interface["description"],
                        "VLAN": host["vlan"],
                        "mode": interface["VLAN"],
                        "speed": interface["speed"],
                        "duplex": interface["duplex"],
                        "type": interface["type"],
                    }
                )

            hosts = hosts.strip(", ")
            output_messages += (
                f"Interface: {interface['interface']}, Description: {interface['description']}, "
                f"Mode: {interface['VLAN']}, Speed: {interface['speed']}, Duplex: {interface['duplex']}, "
                f"Type: {interface['type']}, Hosts: {hosts}\n"
            )

        output_text.append(output_messages)


def main(device_list, target_username, target_password, file_name):
    device_threads = []
    output_text = []
    results_dict = {}
    # Connect to each device in a separate thread
    for target_device in device_list:
        device_worker = Thread(
            target=scrape_switch_details,
            args=(
                target_device,
                target_username,
                target_password,
                output_text,
                results_dict,
            ),
        )
        device_worker.start()
        device_threads.append(device_worker)
    for device_worker in device_threads:
        device_worker.join()

    # Display switch interface results
    for message in output_text:
        print(message)
    print()
    # Output tabulated data to CSV
    csv_lines = [
        [
            "MAC",
            "IP",
            "DNS",
            "Switch",
            "Interface",
            "Description",
            "VLAN",
            "Mode",
            "Speed",
            "Duplex",
            "Type",
        ]
    ]
    for key, value in results_dict.items():
        for port in value["ports"]:
            csv_line = [
                key,
                ",".join(value["ip"]),
                ",".join(value["dns"]),
                port["switch"],
                port["interface"],
                port["description"],
                port["VLAN"],
                port["mode"],
                port["speed"],
                port["duplex"],
                port["type"],
            ]
            csv_lines.append(csv_line)
        try:
            with open(file_name, "w", newline="") as csv_file:
                writer = csv.writer(csv_file)
                writer.writerows(csv_lines)
        except OSError:
            print(f"Unable to write CSV file {file_name}.")
            sys.exit(1)

    sys.exit(0)


if __name__ == "__main__":
    if len(sys.argv) < 5:
        print(
            f"Error: Usage '{sys.argv[0]} [username] [password] [filename] [target device list]'"
        )
        print(
            "Where:\n"
            "username is the username to login as\n"
            "password is base64 encoded password\n"
            "filename for CSV results to be stored in\n"
            "target device list is a space delimited list of devices to connect to"
        )
        sys.exit(1)

    main(
        sys.argv[4:],
        sys.argv[1],
        base64.b64decode(sys.argv[2]).decode("utf-8"),
        sys.argv[3],
    )
