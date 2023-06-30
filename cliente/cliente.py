import socket
import sys
import argparse
import zlib


MAX_BUFFER_SIZE = 1024 * 1
HEADER_SIZE = 1
FCS = 4

TIMEOUT = 2


class ClientUDP:
    def __init__(self, server_address):
        # crea objeto de socket
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        self.server_address = server_address
        # self.retry_limit = 15               # limite para cerrar el socket y salir
        # self.retry_count = 0                # contador


    def contact_server(self, file_name):

        # enviamos solicitud de archivo
        self.send_request(file_name)

        # si recibe True continuamos
        if self.receives_file_existence():
            # Eliminar el tiempo de espera en el socket
            self.sock.settimeout(None)
            print('Respuesta desde el servidor: 200 (Ok)',
                  '\n\t “El archivo si existe en el servidor”')

            # comienza a recibir el archivo
            self.receive_file(file_name)

        else:
            print('Respuesta desde el servidor: 404 (Not found)',
                  '\n\t“El archivo no se encuentra disponible en el servidor”')


    def receive_file(self, file_name):
        expected_seqnum = 0

        with open(file_name, 'wb') as file:

            while True:
                # si !recibe expected_seqnum entonces es None
                data_received = self.receive_data_and_verify_seqnum(expected_seqnum)

                # si no es None continuamos recibiendo y confirmando, amenos que reciba el final b''
                if data_received is not None:

                    # si llego el final
                    if data_received == b'':
                        eof_file = False
                        while not eof_file:
                            self.sock.settimeout(2)
                            # responde confirmacion de que si llego el final
                            self.sock.sendto(b'', self.server_address)

                            # si el cliente no responde quiere decir que si le llego el final
                            try:
                                data, _ = self.sock.recvfrom(MAX_BUFFER_SIZE)
                                if data == b'':
                                    self.sock.sendto(b'', self.server_address)
                            except socket.timeout:
                                eof_file = True
                        print(f"Archivo recibido y guardado: {file_name}")
                        break

                    self.write_data_to_file(file, data_received)

                    # incrementamos expected_seqnum
                    expected_seqnum = self.increment_0_to_255(expected_seqnum)
                    self.send_ack(expected_seqnum)
                    print('')

                else:
                    # Paquete fuera de orden, se reenvía el ACK esperado
                    self.send_ack(expected_seqnum)
                    print(f' de nuevo...')


    def send_request(self, file_name):
        control_message = "REQUEST"
        request_message = f"{control_message} {file_name}"
        self.sock.sendto(request_message.encode(), self.server_address)
        print('Solicitud enviada al servidor.')


    def receives_file_existence(self):
        self.sock.settimeout(TIMEOUT)
        try:
            response_message, _ = self.sock.recvfrom(MAX_BUFFER_SIZE)

            # 6 es el numero de caracteres de 'REPLAY'
            control_message = response_message[:6].decode()
            response_code_bytes = response_message[6:]

            # Extraer el código de respuesta
            response_code = int.from_bytes(response_code_bytes, byteorder='big')

            if control_message == "REPLAY":
                return response_code == 200

        except socket.timeout:
            print("Error: El servidor no respondió en el tiempo especificado.")
            exit(1)


    def send_ack(self, seqnum):
        # codifica a binario
        ack_to_send = seqnum.to_bytes(HEADER_SIZE, byteorder='big')
        self.sock.sendto(ack_to_send, self.server_address)
        print(f'\tACK {seqnum} enviado', end='')


    def write_data_to_file(self, file, data_received):
        # decodifica seqnum
        seqnum_received = int.from_bytes(data_received[:HEADER_SIZE], byteorder='big')
        packet_data = data_received[HEADER_SIZE:]

        try:
            file.write(packet_data)
            print(f"Data({seqnum_received}) guardado")

        except IOError as e:
            print(f"Error al escribir en el archivo: {e}")
            sys.exit()


    # responde con data solo si es el paquete que espera y esta completo sin perdida
    def receive_data_and_verify_seqnum(self, expected_seqnum):
        data, _ = self.sock.recvfrom(MAX_BUFFER_SIZE)
        received_seqnum = int.from_bytes(data[:HEADER_SIZE], byteorder='big')

        if data == b'':  # si es paquete vacio
            return data

        # si llega el seqnum espereado  &&  es correcto el crc32
        elif received_seqnum == expected_seqnum and self.verify_crc32(data):
            return data[:-FCS]

        else:
            print(f"seqnum igual = {received_seqnum} NONE")
            return None


    def verify_crc32(self, data):
        packet = data[HEADER_SIZE:-FCS]
        crc32_bytes = data[-FCS:]

        # crc32 del paquete que se recibio
        crc32_value = zlib.crc32(packet)

        crc32_source = int.from_bytes(crc32_bytes, byteorder='big')

        if crc32_source == crc32_value:
            # print(f'recibido {crc32_value}')
            return True
        else:
            print("\tcrc32 es corrupto...")
            return False


    @staticmethod
    def increment_0_to_255(seqnum):
        return (seqnum + 1) % 256


    def close(self):
        self.sock.close()

# end class ClienteUDP

def main():
    # Crear un objeto ArgumentParser
    parser = argparse.ArgumentParser(description='Programa de cliente')

    # Definir los argumentos aceptados
    parser.add_argument('-f', '--file', type=str, help='Nombre del archivo')

    # Obtener los argumentos pasados al programa
    args = parser.parse_args()
    file_name = args.file

    # Validar los argumentos requeridos
    if not file_name:
        parser.error('Debe proporcionar el nombre del archivo a solicitar.')

    else:
        server_address = ('localhost', 40580)
        client = ClientUDP(server_address)

        try:
            # Iniciar interacción con el servidor
            client.contact_server(file_name)
        finally:
            client.close()


if __name__ == '__main__':
    main()
