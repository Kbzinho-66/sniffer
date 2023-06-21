import platform
import struct
import socket
import sys


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
        if platform.system() == 'Linux':
            try:
                self.s = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, socket.ntohs(3))
            except socket.error:
                print('Could not create socket, try running as super user.')
                sys.exit(1)
        elif platform.system() == 'Windows':
            # TODO(Implementar o socket pra Windows)
            pass

        self._protocols = _get_constants('IPPROTO_')

    def close(self):
        self.s.close()

    def capture(self):
        __IPV4__ = 8
        __ARP__ = 1544
        __IPV6__ = 56710

        # Não sei se precisa dessa divisão aqui, mas por enquanto vou fazer assim
        if platform.system() == 'Linux':
            # Capturar até 2^16 Bytes, o tamanho máximo de um pacote UDP
            raw, _ = self.s.recvfrom(65535)
            dest_mac, src_mac, ethernet_proto = struct.unpack('! 6s 6s H', raw[:14])
            data = raw[14:]

            dest_mac = _get_mac_address(dest_mac)
            src_mac = _get_mac_address(src_mac)
            ethernet_proto = socket.htons(ethernet_proto)

            version_header_len = data[0]
            if ethernet_proto == __IPV4__:
                version = (version_header_len >> 4)
                header_len = (version_header_len & 15) * 4
                ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

                try:
                    protocol = self._protocols[protocol].split('_')[1] + " Protocol"
                except KeyError:
                    protocol = 'None Specified'

                src = '.'.join(map(str, src))
                target = '.'.join(map(str, target))

            elif ethernet_proto == __IPV6__:
                version = (version_header_len & 0xf0) >> 4
                header_len = version_header_len & 0x0f
                ttl, protocol, src, target = struct.unpack('! 8x B B 2x 4s 4s', data[:20])

                try:
                    protocol = self._protocols[protocol].split('_')[1] + " Protocol"
                except KeyError:
                    protocol = 'None Specified'

                numbers = list(map(int, src))
                src = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)

                numbers = list(map(int, target))
                target = '2002:{:02x}{:02x}:{:02x}{:02x}::'.format(*numbers)

            else:
                return None

            return (dest_mac, src_mac, ethernet_proto), (version, header_len, ttl, protocol, src, target)
