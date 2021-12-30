# Notes on Project

## To Do

### Main Functionality

- [x] Currently takes the first packet that is collected, should look at taking
      one with the correct IP address only (`sniffer.py`)
- [x] Create subroutine to decode packet data (`subs.py`)
- [x] Separate sniffer start and request message
  - [ ] Create method of detecting if sniffer already called
  - [ ] Can use session, and after button pressed change the value of a variable
      to true
- [ ] Write subroutine to decode hexadecimal to denary
  - [ ] Add parameter for text conversion as well (boolean flag, default false)
- [ ] Remove length check for decoding subroutines (apart from for final packet
    content to avoid decoding null data)
- [ ] Show full transaction
  - [ ] Need to ensure that TCP headers are the right length (use the length
      section of the header to determine length)
    - [ ] Once completed, can go to subs file and change "decoded" variable
          definition on ~51)
  - [ ] Filter packets from where flags are (i.e. bytes 46-47 = x002, x012, x010
      for syn, syn-ack, ack until x011, x011, x010 for fin-ack, fin-ack, ack)

### Clean Up

- [ ] Remove classes entirely from sniffer, and only do string slicing for packets
      and check for IP addresses and TCP header length

## General Notes

- Run `flask run --host=0.0.0.0` to run the server and allow anyone to access it
Run with the `--with-threads` flag to allow for multiple users to concurrently
access (runs multiple threads)
