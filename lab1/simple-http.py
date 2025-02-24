from pwn import *

def get_ip():
    conn = remote('ipinfo.io', 80)

    conn.send(b"GET /ip HTTP/1.1\r\n"
              b"Host: ipinfo.io\r\n"
              b"User-Agent: pwntools-script\r\n"
              b"Accept: */*\r\n"
              b"Connection: close\r\n\r\n")
    response = conn.recvall().decode()
    #print(response)
    ip = response.split("\r\n")[-1]
    
    print(ip, end="")

if __name__ == "__main__":
    get_ip()
