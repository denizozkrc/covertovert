from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, DNSQR, send, sniff
import random
# import time


class MyCovertChannel(CovertChannelBase):
    """
    - You are not allowed to change the file name and class name.
    - You can edit the class in any way you want (e.g. adding helper functions); however, there must be a "send" and a "receive" function, the covert channel will be triggered by calling these functions.
    """
    def __init__(self):
        """
        - You can edit __init__.
        """
        pass

    # min_msg_length: Minimum message length for the randomized DNS query. Default: 16
    # max_msg_length: Maximum message length for the randomized DNS query. Default: 16
    # bit_chunk_size: Bits to be sent per packet. Can be initialized to the values 1, 2, 4 and 8. Default: 2
    # transaction_id_size: Bit size of the transaction id of DNS query. Fixed value: 16
    # TrID_random_binary_min_size: Minimum string length for the initial randomized transaction id section. Regardless of length, first transaction_id_size bits will be used. Should be bigger than 2. Default value: 3
    # TrID_random_binary_max_size: Maximum string length for the initial randomized transaction id section. Regardless of length, first transaction_id_size bits will be used. Should be bigger than TrID_random_binary_min_size. Default value: 3
    # receiver_IP: IP of the receiver. Default: 172.18.0.3
    # log_file_name: Name of the log file to be used. Default: Example_UDPTimingInterarrivalChannelSender.log
    def send(self, log_file_name, min_msg_length, max_msg_length, bit_chunk_size, receiver_IP, transaction_id_size, TrID_random_binary_min_size, TrID_random_binary_max_size):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        message = self.generate_random_binary_message_with_logging(log_file_name, min_length=min_msg_length, max_length=max_msg_length)
        payload = self.generate_random_message()
        chunks = [message[i:i+bit_chunk_size] for i in range(0, len(message), bit_chunk_size)]
        transaction_id_list = []
        for i in range(len(chunks)):
            transaction_id_list.append(self.encode(chunks[i], bit_chunk_size, transaction_id_size, TrID_random_binary_min_size, TrID_random_binary_max_size))
        # t0 = time.time()
        for transaction_id in transaction_id_list:
            # encode here
            dns_request = IP(dst=receiver_IP)/UDP(dport=53)/DNS(id=transaction_id, qd=DNSQR(qname=payload))
            send(dns_request)
        # t1 = time.time()
        print("Message sent covertly!")
        # print("Time taken to send the message: ", t1-t0)
        # print("bits per scond", 128/(t1-t0))

    # bit_chunk_size: Bits to be sent per packet. Should be same value as the bit_chunk_size in sender. Can be initialized to the values 1, 2, 4 and 8. Default: 2
    # mod_var_init: Initialization for the mod_var variable which checks if the bits received have formed a char yet. Fixed value: 0
    # char_size: Char size. Fixed value: 8
    # terminating_char: Terminating char. The randomizer in the code will always generate strings ending with ".". Depending on the terminating char, can be updated together with the randomizer. Default: "."
    # sender_IP: IP of the receiver. Default: 172.18.0.2
    # log_file_name: Name of the log file to be used. Default: Example_UDPTimingInterarrivalChannelReceiver.log
    def receive(self, sender_IP, log_file_name, bit_chunk_size, mod_var_init, char_size, terminating_char):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        message = []
        message_char = ""
        mod_var = mod_var_init
        stop_sniffing = False
        
        def stop_fnc(packet):
            nonlocal stop_sniffing
            return stop_sniffing

        def process_packet(packet):
            nonlocal mod_var, message_char, message, stop_sniffing
            if packet.haslayer(DNS):
                mod_var += 1
                transaction_id = packet[DNS].id
                chunk = self.decode(transaction_id, bit_chunk_size)
                if message_char == "":
                    message_char = chunk
                else:
                    message_char = message_char + chunk
                if mod_var == char_size // bit_chunk_size:
                    mod_var = mod_var_init
                    message_char = self.convert_eight_bits_to_character(message_char)
                    message.append((message_char))
                    if message_char == terminating_char:
                        stop_sniffing = True
                    else:
                        stop_sniffing = False
                    message_char = ""

        print("Listening for covert data...")
        sniff(filter="udp port 53", prn=process_packet, stop_filter=stop_fnc)

        self.log_message("", log_file_name)

    def encode(self, bit_string, bit_chunk_size, transaction_id_size, TrID_random_binary_min_size, TrID_random_binary_max_size):
        """
        Takes the message part we want to encode
        Returns final transaction id
        """
        value_to_be_sent = int(bit_string, 2)
        transactionID = (self.generate_random_binary_message(TrID_random_binary_min_size, TrID_random_binary_max_size))[:transaction_id_size]  # byte-string
        trans_chunks = [transactionID[i:i+bit_chunk_size] for i in range(0, len(transactionID), bit_chunk_size)]
        trans_int = [int(bitstr, 2) for bitstr in trans_chunks]
        checksum = 0
        for part in trans_int:
            checksum += part
        checksum = checksum % (2**bit_chunk_size)

        while value_to_be_sent != checksum:
            index = random.randint(0, transaction_id_size//bit_chunk_size-1)
            for i in range(bit_chunk_size):
                num = 2**i
                if checksum & num != value_to_be_sent & num:
                    trans_int[index] = trans_int[index] ^ num
                    break
            trans_chunks[index] = format(trans_int[index], f'0{bit_chunk_size}b')
            trans_int = [int(bitstr, 2) for bitstr in trans_chunks]
            checksum = 0
            for part in trans_int:
                checksum += part
            checksum = checksum % (2**bit_chunk_size)
            transactionID = ''.join(trans_chunks)

        transactionID = int(transactionID, 2)
        return transactionID

    def decode(self, transactionID, bit_chunk_size):
        """
        Takes transactionID
        Returns a binary string of length bit_chunk_size
        """
        binary_string_transactionID = format(transactionID, f'0{16}b')
        trans_chunks = [binary_string_transactionID[i:i+bit_chunk_size] for i in range(0, len(binary_string_transactionID), bit_chunk_size)]
        trans_int = [int(bitstr, 2) for bitstr in trans_chunks]
        checksum = 0
        for part in trans_int:
            checksum += part
        checksum = checksum % (2**bit_chunk_size) # got the integer value of the bits
        value = format(checksum, f'0{bit_chunk_size}b')
        return value
