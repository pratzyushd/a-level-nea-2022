# Notes on Project

## To Do

- [x] Currently takes the first packet that is collected, should look at taking
      one with the correct IP address only (`sniffer.py`)
- [x] Create subroutine to decode packet data (`subs.py`)
- [ ] Create separate file for classes of headers and data
  - Load headers from file into classes in python script?
  - Remove classes entirely from sniffer, and only do string slicing for packets
      and check for IP addresses

## General Notes

- Run `flask run --host=0.0.0.0` to run the server and allow anyone to access it
Run with the `--with-threads` flag to allow for multiple users to concurrently
access (runs multiple threads)
