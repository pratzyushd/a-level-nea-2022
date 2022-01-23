# Notes on Project

## To Do

### Main Functionality

- [ ] Collapsible sections for entire transaction
  - [ ] Drop down for each packet, with general description in the title e.g.
  "packet 1: SYN" (primarily only showing SYN, ACK and FIN)
  - [ ] Drop down in each packet for the various headers
  - [ ] Further information / translation on hover?
    - [ ] Information about section and function, byte offset
    - [ ] For HTTP packet data, click to switch between translated version
        and hex representation?
      - Requires use of JS.onclick() function?
- [ ] Front end work
  - [ ] Add CSS beautification

### Completed

- [x] Separate sniffer start and request message
  - [x] Create method of detecting if sniffer already called by that user
  - [x] Can use session, and after button pressed change the value of a variable
      to true
- [x] Add delay to start sniffer button to add resilience
- [x] Currently takes the first packet that is collected, should look at taking
      one with the correct IP address only (`sniffer.py`)
- [x] Create subroutine to decode packet data (`subs.py`)
- [x] Write subroutine to decode hexadecimal to denary
  - [x] Add parameter for text conversion as well (boolean flag, default false)
  - [x] Call the function for specific parameters
- [x] Remove length check for decoding subroutines (apart from for final packet
    content to avoid decoding null data)
- [x] Remove classes entirely from sniffer, and only do string slicing for packets
      and check for IP addresses and TCP header length
- [x] Show full transaction
  - [x] Need to ensure that TCP headers are the right length (use the length
      section of the header to determine length)
    - [x] Once completed, can go to subs file and change "decoded" variable
          definition on ~51)
  - [x] Filter packets from where flags are (i.e. bytes 46-47 = x002, x012, x010
      for syn, syn-ack, ack until x011, x011, x010 for fin-ack, fin-ack, ack)

## General Notes

- Run `flask run --host=0.0.0.0` to run the server and allow anyone to access it
Run with the `--with-threads` flag to allow for multiple users to concurrently
access (runs multiple threads)
