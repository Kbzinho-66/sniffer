from platform import system
import socket

if system() == 'Windows':
    from scapy.all import sniff

    WINDOWS = True
    LINUX = False

elif system() == 'Linux':
    import struct
    import sys

    WINDOWS = False
    LINUX = True


def _get_constants(prefix):
    return dict(
        (getattr(socket, att), att)
        for att in dir(socket)
        if att.startswith(prefix)
    )


def _get_mac_address(bytes_string):
    hex_bytes = map('{:02x}'.format, bytes_string)
    address = ':'.join(hex_bytes).upper()
    return address


class Socket:
    def __init__(self):
        if LINUX:
            try:
                self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            except socket.error:
                print('Could not create socket, try running as super user.')
                sys.exit(1)

        self._protocols = _get_constants('IPPROTO_')

    def _protocol_name(self, protocol):
        try:
            name = self._protocols[protocol].split('_')[1] + " Protocol"
        except KeyError:
            name = 'None Specified'

        return name

    def close(self):
        if LINUX:
            self.s.close()

    def capture(self):
        if LINUX:
            __IPV4__ = 8
            __IPV6__ = 56710

            # Capturar até 2^16 Bytes, o tamanho máximo de um pacote UDP
            raw, _ = self.s.recvfrom(65535)
            dest_mac, src_mac, ethernet_proto = struct.unpack('! 6s 6s H', raw[:14])
            data = raw[14:]

            dest_mac = _get_mac_address(dest_mac)
            src_mac = _get_mac_address(src_mac)
            ethernet_proto = socket.htons(ethernet_proto)

            # A forma de extrair as informações é a mesma
            version_header_len = data[0]
            ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])
            protocol = self._protocol_name(protocol)

            if ethernet_proto == __IPV4__:
                version = (version_header_len >> 4)
                header_len = (version_header_len & 15) * 4

                src = '.'.join(map(str, src))
                target = '.'.join(map(str, target))

            elif ethernet_proto == __IPV6__:
                version = (version_header_len & 0xf0) >> 4
                header_len = version_header_len & 0x0f

                numbers = list(map(int, src))
                src = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)

                numbers = list(map(int, target))
                target = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)

            else:
                return None

            return (dest_mac, src_mac, ethernet_proto), (version, header_len, ttl, protocol, src, target)

        elif WINDOWS:
            __IPV4__ = 2048
            __IPV6__ = 34525

            frame = sniff(count=1)[0]

            if frame.type == __IPV4__ or frame.type == __IPV6__:
                # Extrai as informações comuns aos dois
                dest_mac = frame.dst
                src_mac = frame.src
                ethernet_proto = frame.type
                data = frame.payload
                version = data.version
                src = data.src
                target = data.dst

                # Extrair as informações específicas a cada pacote
                if frame.type == __IPV4__:
                    header_len = int(data.ihl * 32 / 8)
                    ttl = data.ttl
                    protocol = self._protocol_name(data.proto)

                else:
                    header_len = 40
                    ttl = data.hlim
                    protocol = self._protocol_name(data.nh)

                return (dest_mac, src_mac, ethernet_proto), (version, header_len, ttl, protocol, src, target)

            else:
                return None

        else:
            return None
