from Socket import Socket
import sys
import signal


def stop_loop(signum, frame):
    signal.signal(signum, signal.SIG_IGN)
    global interrupt
    interrupt = True


interrupt = False


def main():
    global interrupt
    s = Socket()

    # Criar um arquivo de saída
    with open("result.txt", "w") as file:
        file.write("\n")

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

        if interrupt:
            print('\nOutput was saved to result.txt')
            s.close()
            sys.exit(0)


if __name__ == '__main__':
    signal.signal(signal.SIGINT, stop_loop)
    main()
