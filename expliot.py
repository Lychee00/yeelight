import socket
import ifaddr
from urllib.parse import urlparse
def get_ip_address(ifname):
    """
    Returns the first ipv4 address corresponding to the requested interface

    :param string interface: interface for pre-obtaining ipv4 address

    :returns: ipv4 address of the interface
    """
    for adapter in ifaddr.get_adapters():
        if adapter.name != ifname:
            continue
        for ip in adapter.ips:
            if not isinstance(ip.ip, tuple):  # not IPv6
                return ip.ip
    return None


def discover_bulbs(timeout=5, interface=False):
    s = send_discovery_packet(timeout, interface)

    bulbs = []
    bulb_ips = set()
    while True:
        try:
            data, addr = s.recvfrom(65507)
        except socket.timeout:
            break

        capabilities = parse_capabilities(data)
        parsed_url = urlparse(capabilities["Location"])

        bulb_ip = (parsed_url.hostname, parsed_url.port)
        if bulb_ip in bulb_ips:
            continue

        capabilities = filter_lower_case_keys(capabilities)
        bulbs.append(
            {"ip": bulb_ip[0], "port": bulb_ip[1], "capabilities": capabilities}
        )
        bulb_ips.add(bulb_ip)

    return bulbs


def send_discovery_packet(timeout=2, interface=False, ip_address="239.255.255.250"):
    """
    Send SSDP query packets

     :param int timeout: how long to wait for a response. Because we don't know when all the bulbs will end responding
    
     :param string interface: The interface that should be used for broadcast packets (currently only for ipv4)

     :param string ip_address: The address to send ssdp broadcast packets. If there is a specified object, it will be sent to the specified object, otherwise it will be processed as a broadcast packet.
                               Multicast address: 239.255.255.250 is SSDP (Simple Service Discovery Protocol),
                               This is the protocol used by the router's UPNP service.
    
     :return: socket for sending packets

    """
    msg = "\r\n".join(
        [
            "M-SEARCH * HTTP/1.1",
            "HOST: " + ip_address + ":1982",
            'MAN: "ssdp:discover"',
            "ST: wifi_bulb",
        ]
    )

    # Set up the UDP socket.
    s = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    s.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 32)
    if interface:
        s.setsockopt(
            socket.IPPROTO_IP,
            socket.IP_MULTICAST_IF,
            socket.inet_aton(get_ip_address(interface)),
        )
    s.settimeout(timeout)
    s.sendto(msg.encode(), (ip_address, 1982))
    # print(ip_address)
    return s


def parse_capabilities(data):
    """
    Example:
    'HTTP/1.1 200 OK
    Cache-Control: max-age=3600
    Date:
    Ext:
    Location: yeelight://10.0.7.184:55443
    Server: POSIX UPnP/1.0 YGLC/1
    id: 0x00000000037073d2
    model: color
    fw_ver: 76
    ...'

    Example:
    {
        'Location': 'yeelight://10.0.7.184:55443',
        'Server': 'POSIX UPnP/1.0 YGLC/1',
        'id': '0x00000000037073d2',
        'model': 'color',
        'fw_ver': '76',
        ...
    }
    """
    return dict(
        [x.strip("\r").split(": ") for x in data.decode().split("\n") if ":" in x]
    )


def filter_lower_case_keys(dict):
    return {key: value for key, value in dict.items() if key.islower()}

def show_paylaod():

    choice = input(
        '''
        
        Enter the serial number of the desired operation:

         1. Turn on the bulb
         2. Turn off the bulb
         3. Set the bulb brightness
         4. Set the bulb rgb
         5. Set the bulb hsv
         6. Change the color temperature
         7. Toggle the bulb 
        
        '''
    )

    return choice

def exp( ip, port=55443, status='off'):

    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.connect((ip, port))
    

    turn_on = b'{"id":0,"method":"set_power","params":["on","smooth",300]}\r\n'
    turn_off = b'{"id":0,"method":"set_power","params":["off","smooth",300]}\r\n'
    set_bright = b'{"id":0,"method":"set_bright","params":[60,"smooth",300]}\r\n'
    set_rgb = b'{"id":1,"method":"set_rgb","params":[65280,"smooth",300]}\r\n'
    set_hsv = b'{"id":2,"method":"set_hsv","params":[359,100,"smooth",300]}\r\n'
    set_ct_abx = b'{"id":3,"method":"set_ct_abx","params":[1700,"smooth",300]}\r\n'
    toggle = b'{"id":0,"method":"toggle","params":["smooth",300]}\r\n'

    payload = {
        '1' : b'{"id":0,"method":"set_power","params":["on","smooth",300]}\r\n',
        '2' : b'{"id":0,"method":"set_power","params":["off","smooth",300]}\r\n',
        '3' : b'{"id":0,"method":"set_bright","params":[60,"smooth",300]}\r\n',
        '4' : b'{"id":1,"method":"set_rgb","params":[65280,"smooth",300]}\r\n',
        '5' : b'{"id":2,"method":"set_hsv","params":[359,100,"smooth",300]}\r\n',
        '6' : b'{"id":3,"method":"set_ct_abx","params":[1700,"smooth",300]}\r\n',
        '7' : b'{"id":0,"method":"toggle","params":["smooth",300]}\r\n',
    }


    if status == 'off':
        print('The bulb is off at this time, it has been turned on first')
        s.send(turn_on)
        s.send(b" ")

    action = show_paylaod()
    while action:
        s.send(payload[action])
        s.send(b" ")
        data = s.recv(16 * 1024)
        print(data)
        action = show_paylaod()

def main():
    print('++++++++++++++++++++++++++++++++++++++++++++++++')
    print('+          Yeelight Bulbs Discovering          +')
    print('++++++++++++++++++++++++++++++++++++++++++++++++')
    bulbs = discover_bulbs(5)
    print('Found yeelight bulb in LAN:  {}'.format(str(len(bulbs))))
    if len(bulbs) != 0:
        for index,bulb in enumerate(bulbs):
            print('No. {} device information'.format(str(index+1)))
            print('IP:' + bulb['ip'])
            print('Port:' + str(bulb['port']))

            print('Power:' + bulb['capabilities']['power'])
            print('Set Bright:' + bulb['capabilities']['bright'])


        num = int(input('Choose the number you want to control: '))
        ip = bulbs[num-1]['ip']
        status = bulbs[num-1]['capabilities']['power']
        exp(ip,55443,status)
    else:
        print('\nCan\'t find bulbs for now, please try later.\n Please make sure the device is on the same LAN as the light bulb and don\'t try too many times in a short period of time\n')

if __name__ == '__main__':
    main()