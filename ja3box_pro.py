import time
import json
import random
import hashlib
import argparse
import datetime
import warnings
import collections.abc
from itertools import cycle

from scapy.utils import PcapWriter
from colorama import Fore, Style, init as Init
from scapy.all import sniff, load_layer, Ether, bind_layers, TCP

# Ignore specific warnings
warnings.filterwarnings('ignore')

# 兼容 win 的颜色输出
Init()


def get_attr(obj, attr, default=""):
    value = getattr(obj, attr, default)
    if value is None:
        value = default
    return value


def timer_unit(s):
    if s <= 1:
        return f'{round(s, 1)}s'
    num, unit = [(i, u) for i, u in ((s / 60**i, u) for i, u in enumerate('smhd')) if i >= 1][-1]
    return f'{round(num, 1)}{unit}'


def put_color(string, color, bold=True):
    if color == 'gray':
        COLOR = Style.DIM + Fore.WHITE
    else:
        COLOR = getattr(Fore, color.upper(), "WHITE")
    return f'{Style.BRIGHT if bold else ""}{COLOR}{str(string)}{Style.RESET_ALL}'


def Print(data):
    if output_filename == 'stdout':
        if need_json:
            print(' ' * 15, '\r' + json.dumps(data, indent=4,), end='\n\n')
        else:
            print(data, end='\n\n')
    else:
        if need_json:
            with open(output_filename, 'a') as fp:
                json.dump(data, fp)
                fp.write('\n')
        else:
            with open(output_filename, 'a') as fp:
                fp.write(data + '\n')


def concat(data, delete_grease=False):
    result = []
    for i, d in enumerate(data):
        if isinstance(d, collections.abc.Iterable):
            result.append('-'.join(map(
                str,
                remove_grease(d) if delete_grease else d
            )))
        else:
            result.append(str(d))
    return ','.join(result)


def remove_grease(value):
    return [i for i in value if i not in GREASE_TABLE]


def collector(pkt):
    global COUNT, COUNT_SERVER, COUNT_CLIENT, NEW_BIND_PORTS

    COUNT += 1

    if savepcap:
        pcap_dump.write(pkt)

    print(f'[*] running... {put_color(next(roll), "green")}', end='\r')

    tcp_layer = pkt.getlayer('TCP')
    if tcp_layer is None:
        return

    IP_layer = pkt.getlayer("IP") or pkt.getlayer("IPv6")

    src_ip = IP_layer.src
    src_port = pkt.getlayer("TCP").sport

    dst_ip = IP_layer.dst
    dst_port = pkt.getlayer("TCP").dport

    layer = get_attr(tcp_layer[0], 'msg')
    if not layer:
        if pkt.lastlayer().name != 'Raw':
            return

        if src_port in NEW_BIND_PORTS[0] and dst_port in NEW_BIND_PORTS[1]:
            return

        bind_layers(TCP, TLS, sport=src_port)  # noqa: F821
        bind_layers(TCP, TLS, dport=dst_port)  # noqa: F821

        NEW_BIND_PORTS[0].add(src_port)
        NEW_BIND_PORTS[1].add(dst_port)

        pkt = Ether(pkt.do_build())
        tcp_layer = pkt.getlayer('TCP')
        layer = get_attr(tcp_layer[0], 'msg')
        if not layer:
            return

    layer = layer[0]
    name = layer.name

    if not name.endswith('Hello'):
        return

    from_type = 0
    from_name = 'Server'
    fp_name = 'ja3s'

    if name.startswith('TLS') or name.startswith('SSL'):
        if 'Client' in name:
            if ja3_type not in ["ja3", "all"]:
                return

            from_type = 1
            from_name = 'Client'
            fp_name = 'ja3'

        elif ja3_type not in ["ja3s", "all"]:
            return
    else:
        return

    server_name = 'unknown'

    Version = layer.version
    Cipher = get_attr(layer, 'ciphers' if from_type else 'cipher')

    exts = get_attr(layer, 'ext')
    if exts:
        Extensions_Type = list(map(lambda c: c.type, exts))

        if from_type:
            try:
                loc = Extensions_Type.index(0)
            except ValueError:
                server_name = 'unknown'
            else:
                server_names = get_attr(exts[loc], 'servernames')

                if server_names:
                    server_name = get_attr(
                        server_names[0],
                        'servername', 'unknown'
                    ).decode('utf8')

            try:
                loc = Extensions_Type.index(11)
            except IndexError:
                EC_Point_Formats = []
            else:
                EC_Point_Formats = get_attr(exts[loc], 'ecpl')

            try:
                loc = Extensions_Type.index(10)
            except IndexError:
                Elliptic_Curves = []
            else:
                Elliptic_Curves = get_attr(exts[loc], 'groups')

    else:
        Extensions_Type = Elliptic_Curves = EC_Point_Formats = []

    if from_type:
        COUNT_CLIENT += 1
        value = [
            Version, Cipher, Extensions_Type,
            Elliptic_Curves, EC_Point_Formats
        ]

    else:
        COUNT_SERVER += 1
        value = [Version, Cipher, Extensions_Type]

    raw_fp = concat(value)
    raw_fp_no_grease = concat(value, delete_grease=True)

    md5_fp = hashlib.md5(raw_fp.encode('utf8')).hexdigest()
    md5_fp_no_grease = hashlib.md5(raw_fp_no_grease.encode('utf8')).hexdigest()

    handshake_type = name.split(' ')[0]
    if need_json:
        json_data = {
            'from': from_name,
            'type': handshake_type,
            'src': {
                'ip': src_ip,
                'port': src_port,
            },
            'dst': {
                'ip': dst_ip,
                'port': dst_port,
            },
            fp_name: {
                'str': raw_fp,
                'md5': md5_fp,
                'str_no_grease': raw_fp_no_grease,
                'md5_no_grease': md5_fp_no_grease,
            }
        }

        if from_type:
            json_data['dst']['server_name'] = server_name

        Print(json_data)
    else:
        color_data = '\n'.join([
            f'[+] Hello from {put_color(from_name, "cyan", bold=False)}',
            f'  [-] type: {put_color(handshake_type, "green")}',
            f'  [-] src ip: {put_color(src_ip, "cyan")}',
            f'  [-] src port: {put_color(src_port, "white")}',
            f'  [-] dst ip: {put_color(dst_ip, "blue")}' + (
                f' ({put_color(server_name, "white")})' if from_type else ''
            ),
            f'  [-] dst port: {put_color(dst_port, "white")}',
            f'  [-] {fp_name}: {raw_fp}',
            f'  [-] {fp_name}_no_grease: {raw_fp_no_grease}',
            f'  [-] md5: {put_color(md5_fp, "yellow")}',
            f'  [-] md5_no_grease: {put_color(md5_fp_no_grease, "yellow")}',
        ])
        Print(color_data)


VERSION = '2.2'

print(f'''
{Style.BRIGHT}{Fore.YELLOW}  ________
{Style.BRIGHT}{Fore.YELLOW} [__,.,--\\\\{Style.RESET_ALL} __     ______
{Style.BRIGHT}{Fore.YELLOW}    | |    {Style.RESET_ALL}/ \\\\   |___ //
{Style.BRIGHT}{Fore.YELLOW}    | |   {Style.RESET_ALL}/ _ \\\\    |_ \\\\
{Style.BRIGHT}{Fore.YELLOW}  ._| |  {Style.RESET_ALL}/ ___ \\\\  ___) ||  toolbox
{Style.BRIGHT}{Fore.YELLOW}  \\__// {Style.RESET_ALL}/_//  \\_\\\\|____//   v{Fore.GREEN}{VERSION}{Style.RESET_ALL}
''')

parser = argparse.ArgumentParser(description=f'Version: {VERSION}; Running in Py3.x')
parser.add_argument(
    "-i", default='Any',
    help="interface or list of interfaces (default: sniffing on all interfaces)"
)
parser.add_argument(
    "-p", default=None, type=int,
    help="port to monitor"
)
parser.add_argument(
    "-f", default=None,
    help="local pcap filename (in the offline mode)"
)
parser.add_argument(
    "-of", default='stdout',
    help="print result to? (default: stdout)"
)
parser.add_argument(
    "-bpf", default=None, help="yes, it is BPF"
)

parser.add_argument(
    "-jtype", default="all",
    choices=["ja3", "ja3s", "all"], help="get pure ja3/ja3s"
)

parser.add_argument(
    "--json", action="store_true", help="print result as json"
)
parser.add_argument(
    "--savepcap", action="store_true",
    help="save the raw pcap"
)
parser.add_argument(
    "-pf",
    default=datetime.datetime.now().strftime("%Y.%m.%d-%X"),
    help="eg. `-pf test`: save the raw pcap as test.pcap"
)



args = parser.parse_args()

COUNT = COUNT_SERVER = COUNT_CLIENT = 0
GREASE_TABLE = {
    0x0a0a, 0x1a1a, 0x2a2a, 0x3a3a,
    0x4a4a, 0x5a5a, 0x6a6a, 0x7a7a,
    0x8a8a, 0x9a9a, 0xaaaa, 0xbaba,
    0xcaca, 0xdada, 0xeaea, 0xfafa
}

NEW_BIND_PORTS = [set(), set()]
roll = cycle('\\|-/')

bpf = args.bpf
need_json = args.json
output_filename = args.of
savepcap = args.savepcap
pcap_filename = args.pf
iface = args.i
ja3_type = args.jtype
port = args.p

if savepcap:
    pcap_dump = PcapWriter(
        f'{pcap_filename}.pcap',
        append=True,
        sync=True
    )

sniff_args = {
    'prn': collector,
    'filter': bpf,
    'store': 0,  # DO NOT SET store to 1
    'iface': iface if iface != 'Any' else None,
}

if port:
    sniff_args['filter'] = f"tcp port {port}" if not bpf else f"tcp port {port} and ({bpf})"

if args.f:
    filename = args.f
    sniff_args['offline'] = filename
    print(f'[*] mode: {put_color("offline", "yellow")}')
    print(f'[*] filename: {put_color(filename, "white")}', end='\n\n')
else:
    print(f'[*] mode: {put_color("online", "green")}')
    print(f'[*] iface: {put_color(iface, "white")}', end='\n\n')

print(f'[*] BPF: {put_color(bpf, "white")}')
print(f'[*] port: {put_color(port, "white")}')
print(f'[*] type filter: {put_color(ja3_type, "white")}')
print(f'[*] output filename: {put_color(output_filename, "white")}')
print(f'[*] output as json: {put_color(need_json, "green" if need_json else "white", bold=False)}')
print(f'[*] save raw pcap: {put_color(savepcap, "green" if savepcap else "white", bold=False)}')

if savepcap:
    print(f'[*] saved in: {put_color(pcap_filename, "white")}.pcap')

print()

load_layer("tls")

start_ts = time.time()

try:
    sniff(**sniff_args)
except Exception as e:
    print(f'[!] {put_color(f"Something went wrong: {e}", "red")}')

end_ts = time.time()
print(
    '\r[+]',
    f'all packets: {put_color(COUNT, "cyan")};',
    f'client hello: {put_color(COUNT_CLIENT, "cyan")};',
    f'server hello: {put_color(COUNT_SERVER, "cyan")};',
    f'in {put_color(timer_unit(end_ts - start_ts), "white")}'
)

print(
    '\n\r[*]',
    put_color(
        random.choice([
            u"goodbye", u"have a nice day", u"see you later",
            u"farewell", u"cheerio", u"bye",
        ]) + random.choice(['...', '~~', '!', ' :)']), 'green'
    )
)
