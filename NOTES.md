# To Do

- [ ] Currently takes the first packet that is collected, should look at taking
      one with the correct IP address only (`sniffer.py`)
- [ ] Create subroutine to decode packet data (`subs.py`)

# General Notes 

- Run `flask run --host=0.0.0.0` to run the server and allow anyone to access it
Run with the `--with-threads` flag to allow for multiple users to concurrently
access (runs multiple threads)
