from Socket import Socket
import sys


def main():
    s = Socket()

    # Criar um arquivo de saída
    with open("result.txt", "w") as file:
        file.write("\n")

    try:
        while True:
            packet = s.capture()
            if packet:
                (dest_mac, src_mac, ethernet_proto), (version, header_len, ttl, protocol, src, target) = packet

                fmt = (
                    'Ethernet Frame:\n'
                    f'\tDestination: {dest_mac}, Source: {src_mac}, Ethernet Protocol: {ethernet_proto}\n'
                    f'IPv{version} Packet:\n'
                    f'\tHeader length: {header_len}, TTL: {ttl}\n'
                    f'\t{protocol}, Source: {src}, Target: {target}\n'
                )

                print(fmt)
                with open("result.txt", "a") as file:
                    file.write(fmt)
                    file.write("\n")

    except KeyboardInterrupt:
        print('\nOutput was saved to result.txt')
        s.close()
        sys.exit(130)


if __name__ == '__main__':
    main()
