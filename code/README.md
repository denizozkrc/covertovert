#  CSC-PSV-DNS-TID
Covert Storage Channel that exploits Protocol Field Manipulation using Transaction ID field in DNS.

## Sender

### Generating the Message
To encode the data, first a random binary string is constructed that ends with the predetermined terminating character ".". 

### Encoding the Data
- To encode the message, the string is separated into `bit_chunk_size` sized chunks.
- For each chunk, a random transaction id is generated. 
- Then, this randomized transaction id is seperated into `bit_chunk_size` sized chunks and these chunks are summed up to find a `bit_chunk_size` sized checksum.
- If this checksum is equal to the chunk of data we want to send, then the encoding is over and the determined transaction id is sent. 
If not, a random chunk from the transaction id is chosen and one of the bits is flipped. The bit to flipped is determined by the difference between the checksum and the chunk to be sent. For example, if first of checksum is 0 but the first bit of the chunk to be sent is 1, then the first bit of the selected chunk from the transaction id is flipped. The checksum is then computed again. And this step is repeated.

## Receiver

### Decoding the Data
- To decode the message, the transaction id is separated into `bit_chunk_size` sized chunks and these chunks are summed up to find a `bit_chunk_size` sized checksum.
- The resulted checksum is the chunk that was intended to be sent in sender.
- The checksum is appended to the message char string at hand. When size of message char string reaches 8 bits, we convert it to the representative char, append to out message and reinitialize message char string to an empty string.
- When "." is received, stop_filter returns true and the receiver stops listening.


## Parameters
- **covert_channel_code:** Code of the covert channel. For this implementation it is CSC-PSV-DNS-TID.

### Sender Parameters
- **min_msg_length:** Minimum message length for the randomized DNS query. Default: 16

- **max_msg_length:** Maximum message length for the randomized DNS query. Default: 16

- **bit_chunk_size:** Bits to be sent per packet. Can be initialized to the values 1, 2, 4 and 8. Default: 2

- **transaction_id_size:** Bit size of the transaction id of DNS query. Fixed value: 16

- **TrID_random_binary_min_size:** Minimum string length for the initial randomized transaction id section. Regardless of length, first transaction_id_size bits will be used. Should be bigger than 2. Default value: 3

- **TrID_random_binary_max_size:**  Maximum string length for the initial randomized transaction id section. Regardless of length, first transaction_id_size bits will be used. Should be bigger than TrID_random_binary_min_size. Default value: 3

- **receiver_IP:** IP of the receiver. Default: 172.18.0.3

- **log_file_name:** Name of the log file to be used. Default: Example_UDPTimingInterarrivalChannelSender.log

### Receiver Parameters
- **bit_chunk_size:** Bits to be sent per packet. Should be same value as the bit_chunk_size in sender. Can be initialized to the values 1, 2, 4 and 8. Default: 2

- **mod_var_init:** Initialization for the mod_var variable which checks if the bits received have formed a char yet. Fixed value: 0

- **char_size:** Char size. Fixed value: 8

- **terminating_char:** Terminating char. The randomizer in the code will always generate strings ending with ".". Depending on the terminating char, can be updated together with the randomizer. Default: "."

- **sender_IP:** IP of the receiver. Default: 172.18.0.2

- **log_file_name:**  Name of the log file to be used. Default: Example_UDPTimingInterarrivalChannelReceiver.log


## Covert Channel Capacity
In order to measure the capacity, we used the python `time` module. 
- We called the `time()` function before sending the first packet and assigned its value to the variable t0. This function returns the time in seconds since epoch (the point where time begins).
- We called the `time()` function after sending the last packet and assigned its value to the variable t1.
- We calculated time passed between first and last packets by calculating (t1-t0). 
- We divided 128 by this value and ended up with covert channel capacity in bits per second.

**Measured capacity:** 17.84 bits per second (for `bit_chunk_size`=2)
