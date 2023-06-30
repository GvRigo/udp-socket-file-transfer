import socket
import os
import zlib


MAX_BUFFER_SIZE = 1024 * 1
HEADER_SIZE = 1
FCS = 4
BYTES_WITHOUT_HEADERS = MAX_BUFFER_SIZE - HEADER_SIZE - FCS

TIMEOUT = 2


class ServerUDP:
    address = ''
    port = 0
    # tupla ip & puerto
    address_client = ()

    def __init__(self, address, port):
        self.address = address
        self.port = port


    def start(self):
        self.sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        # asocia socket con address
        self.sock.bind((self.address, self.port))
        self.receive_requests()


    def receive_requests(self):
        print('Esperando a recibir mensajes ...')
        data, self.address_client = self.sock.recvfrom(MAX_BUFFER_SIZE)
        message = data.decode()
        print(f"Cliente {self.address_client}:\n\t{message}")

        if message.startswith('REQUEST'):
            file_name = self.read_file_name(message)

            if os.path.exists(file_name):
                response_code, t_bytes = 200, 1
                self.replay_to_client(response_code, t_bytes)
                self.send_file_packets(file_name)
            else:
                response_code, t_bytes = 400, 2
                self.replay_to_client(response_code, t_bytes)
        else:
            pass


    def replay_to_client(self, response_code, t_bytes):
        control_message = "REPLAY".encode()
        message = control_message + response_code.to_bytes(t_bytes, byteorder='big')
        self.sock.sendto(message, self.address_client)
        print(f'Respuesta enviada a {self.address_client} {response_code}\n')


    def read_file_name(self, message):
        # busca la primera aparicion inicio-fin, devuelve su indice, sino encuentra -> -1
        start_index = message.find('"')

        # la ultima apacion de fin-inicio y devuelve su indice, sino encuentra -> -1
        end_index = message.rfind('"')

        if start_index != -1 and end_index != -1 and (start_index < end_index):
            # 
            file_name = message[ start_index + 1 : end_index ]
            return file_name
        else:
            # agregamos solo el segundo que esta despues del espacio
            file_name = message.split(' ', 1)[1]
            return file_name


    def send_file_packets(self, file_name):
        seqnum = 0  # iniciamos seqnum

        # mantenemos el archivo abierto y se cierra automatico
        with open(file_name, "rb") as file:
            # lee una vez un packet del archivo e inicia el expected_ack
            packet = file.read(BYTES_WITHOUT_HEADERS)
            expected_ack = 1

            '''
            mientras 'packet' hay datos en el archivo y
            no sale de alli hasta terminar de leer todo el archivo...
            '''

            while packet:
                # enviamos y recibimos ack esperado -> recibimos True si es correcto
                is_ack_received = self.send_packet_and_receive_ack(packet, seqnum, expected_ack)

                if is_ack_received:
                    seqnum = self.increment_0_to_255(seqnum)

                # lee lo siguiente que enviaremos
                packet = file.read(BYTES_WITHOUT_HEADERS)
                expected_ack = self.increment_0_to_255(expected_ack)

        # ultimo paquete solo para confirmar que llego el final
        self.send_eof_packet()


    def send_packet_and_receive_ack(self, packet, seqnum, expected_ack):
        is_ack_received = False

        # mientras falso
        while not is_ack_received:
            self.send_packet(packet, seqnum)

            # recibimos y verificamos ack -> True or False
            received_ack = self.receive_and_verify_ack(expected_ack)

            if received_ack:
                is_ack_received = True

        return is_ack_received


    # si no lleva el indicado devuelve True or False
    def receive_and_verify_ack(self, expected_ack):
        self.sock.settimeout(TIMEOUT)  # fija tiempo de espera
        try:
            data, _ = self.sock.recvfrom(MAX_BUFFER_SIZE)

            #decodifica a decimal received_ack
            received_ack = int.from_bytes(data[:HEADER_SIZE], byteorder='big')

            if received_ack == expected_ack:
                return True

        except socket.timeout:
            return False


    def send_packet(self, packet, seqnum):
        # Convertir el numero de secuencia en bytes
        seqnum_bytes = seqnum.to_bytes(HEADER_SIZE, byteorder='big')

        # Calcular el CRC32 del paquete
        crc32_value = zlib.crc32(packet)

        # Convertir el valor CRC32 en bytes
        crc32_bytes = crc32_value.to_bytes(FCS, byteorder='big')

        # Concatenar el numero de secuencia, el paquete y el CRC32
        message =  seqnum_bytes + packet + crc32_bytes

        # Enviar el mensaje al cliente
        self.sock.sendto(message, self.address_client)

        # Se construye la cadena a imprimir
        output = f"Mensaje enviado: Seqnum = {seqnum} - Tipo = DATA, Bytes = {len(message)}"

        # Agrega el caracter de retroceso al principio de la cadena y usa flush=True
        print("\r" + output, end="", flush=True)
        print()  # eliminamos para que funcione lo de arriba


    def send_eof_packet(self):
        self.sock.settimeout(TIMEOUT)
        is_eof_received = False

        while not is_eof_received:
            self.sock.sendto(b'', self.address_client)
            # print(f"Archivo enviado... esperando confirmacion de recibido...")
            try:
                data, _ = self.sock.recvfrom(MAX_BUFFER_SIZE)
                if data ==  b'':
                    is_eof_received = True

            except socket.timeout:
                print("tiempo execedido.. reenviando eof")
                pass


    @staticmethod
    def increment_0_to_255(seqnum):
        return (seqnum + 1) % 256

# end of class



def start_server():
    server = ServerUDP('localhost', 40580)
    server.start()


# Iniciamos servidor
while True:
    start_server()

####################
