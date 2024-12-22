from CovertChannelBase import CovertChannelBase
from scapy.all import IP, UDP, DNS, DNSQR, send

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
    def send(self, log_file_name, min_msg_length, max_msg_length, bit_chunk_size, receiver_IP):
        """
        - In this function, you expected to create a random message (using function/s in CovertChannelBase), and send it to the receiver container. Entire sending operations should be handled in this function.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        message = self.generate_random_binary_message_with_logging(log_file_name, min_length=min_msg_length, max_length=max_msg_length)
        payload = self.generate_random_message()
        chunks = [message[i:i+bit_chunk_size] for i in range(len(message), bit_chunk_size)]
        for chunk in chunks:
            transaction_id = int.from_bytes(chunk.encode('utf-8'), byteorder='big')
            dns_request = IP(dst=receiver_IP)/UDP(dport=53)/DNS(id=transaction_id, qd=DNSQR(qname=payload))
            send(dns_request)
        print("Message sent covertly!")

    def receive(self, parameter1, parameter2, parameter3, log_file_name):
        """
        - In this function, you are expected to receive and decode the transferred message. Because there are many types of covert channels, the receiver implementation depends on the chosen covert channel type, and you may not need to use the functions in CovertChannelBase.
        - After the implementation, please rewrite this comment part to explain your code basically.
        """
        self.log_message("", log_file_name)
