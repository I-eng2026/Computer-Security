import ipaddress
import pandas as pd

ip_list = [
    "127.0.0.32",
    "148.148.161.76",
    "135.227.220.90",
    "227.256.184.29",
    "250.82.243.171",
    "139.42.224.211",
    "230.214.25.34",
    "77.61.109.143",
    "171.29.999.111",
    "10.41.166.8",
    "253.256.178.226",
    "192.168.114.153",
    "172.25.222.3",
    "193.200.104.12",
    "240.194.88.204"
]

def get_ip_class(ip):
    first_octet = int(ip.split('.')[0])
    if first_octet >= 0 and first_octet <= 127:
        return 'A' if first_octet != 127 else 'Special'
    elif first_octet >= 128 and first_octet <= 191:
        return 'B'
    elif first_octet >= 192 and first_octet <= 223:
        return 'C'
    elif first_octet >= 224 and first_octet <= 239:
        return 'D'
    elif first_octet >= 240 and first_octet <= 254:
        return 'E'
    else:
        return 'N/A'

def get_default_mask(ip_class):
    return {
        'A': '255.0.0.0',
        'B': '255.255.0.0',
        'C': '255.255.255.0'
    }.get(ip_class, 'Not Applicable')

def is_rfc1918(ip_obj):
    return ip_obj.is_private

# Store results
results = []

for ip in ip_list:
    try:
        ip_obj = ipaddress.IPv4Address(ip)
        valid = 'Y'
        ip_class = get_ip_class(ip)
        rfc1918 = 'Y' if is_rfc1918(ip_obj) else 'N'
        default_mask = get_default_mask(ip_class)
        numeric = int(ip_obj)
    except ipaddress.AddressValueError:
        valid = 'N'
        ip_class = 'N/A'
        rfc1918 = 'N'
        default_mask = 'Not Applicable'
        numeric = 'Not Applicable'

    results.append({
        "IP Address": ip,
        "Class": ip_class,
        "Valid (Y/N)": valid,
        "RFC 1918 (Y/N)": rfc1918,
        "Default Mask": default_mask,
        "Numeric Representation": numeric
    })

# Convert to DataFrame and display
df = pd.DataFrame(results)
import ace_tools as tools; tools.display_dataframe_to_user(name="IP Address Analysis", dataframe=df)
