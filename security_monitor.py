import socket
import platform
import os
import datetime

target_host = "127.0.0.1"
common_ports = [21, 22, 23, 25, 53, 80, 443, 3306, 8080]
report_file = "security_report.txt"

def get_system_info():
    system_name = platform.system()
    release_version = platform.release()
    return f"{system_name} {release_version}"

def check_root_privileges():
    try:
        return os.geteuid() == 0
    except AttributeError:
        return False

def scan_ports(ip, ports):
    open_ports_list = []
    for port in ports:
        sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        sock.settimeout(1)
        result = sock.connect_ex((ip, port))
        if result == 0:
            open_ports_list.append(port)
        sock.close()
    return open_ports_list

def generate_report():
    timestamp = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    os_info = get_system_info()
    
    print(f"start_audit: {timestamp}")
    print(f"system: {os_info}")
    
    open_ports = scan_ports(target_host, common_ports)
    
    with open(report_file, "w") as f:
        f.write("security audit report\n")
        f.write(f"date: {timestamp}\n")
        f.write(f"target_host: {target_host}\n")
        f.write(f"os_version: {os_info}\n")      
        f.write("\nport_scan_results:\n")
        if open_ports:
            for p in open_ports:
                service_name = "unknown"
                try:
                    service_name = socket.getservbyport(p)
                except:
                    pass
                line = f"port_{p}: open ({service_name})\n"
                print(line.strip())
                f.write(line)
                
                if p == 21 or p == 23:
                    f.write("insecure protocol detected telnet and ftp\n")
        else:
            f.write("no critical open ports found\n")
            

    print(f"audit finished. report saved to: {report_file}")

if __name__ == "__main__":
    generate_report()
