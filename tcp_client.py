#!/bin/python3

import socket
import binascii
import time
import threading
import os

HOST = '127.0.0.1'
PORT = 10001

# 전송할 HEX 문자열
hex_str = [
    "00 00 00 00 29 1A 00",       # vrx_get_telemetries()

    # "00 00 00 00 46 12 00",       # hstx_get_status_register()
    # "00 00 00 00 46 13 00",       # hstx_get_ready_register()
    # "00 00 00 00 46 05 00",       # hstx_reset_register()

    # "00 00 00 00 46 00 00",       # hstx_get_control_register()
    
    # "00 00 00 00 46 C0 00",       # hstx_set_pa_disable_configuration()
    # "00 00 00 00 46 00 00",       # hstx_get_control_register()
    
    # "00 00 00 00 46 C1 00",       # hstx_set_pa_disable_synchronisation()
    # "00 00 00 00 46 00 00",       # hstx_get_control_register()
    
    # "00 00 00 00 46 C2 00",       # hstx_set_pa_enable_synchronisation()
    # "00 00 00 00 46 00 00",       # hstx_get_control_register()
    
    # "00 00 00 00 46 C3 00",       # hstx_set_pa_enable_data()
    # "00 00 00 00 46 00 00",       # hstx_get_control_register()
    
    # "00 00 00 00 46 C4 00",       # hstx_set_pa_enable_test_data()
    # "00 00 00 00 46 00 00",       # hstx_get_control_register()
]

def unhexlify(s: str) -> bytes:
    # 공백 무시하고 16진수 → bytes
    return binascii.unhexlify("".join(s.split()))

def to_hex(b: bytes) -> str:
    # bytes → "AA BB CC ..." 형식 문자열
    h = binascii.hexlify(b).decode().upper()
    return " ".join(h[i:i+2] for i in range(0, len(h), 2))

# data = [unhexlify(s) for s in hex_str]


def recv_loop(sock: socket.socket, disconnected: threading.Event):
    """서버에서 오는 데이터를 계속 수신해서 출력"""
    try:
        while True:
            data = sock.recv(4096)
            if not data:
                print("\n[!] 서버가 연결을 종료했습니다.")
                disconnected.set()
                return
            print(f"\nRecv({len(data)}): {to_hex(data)}")
    except OSError as e:
        # 소켓이 닫히면 여기로 들어올 수 있음
        print(f"\n[!] 수신 에러: {e}")
        # os._exit(1)
        disconnected.set()

def main():
    while True:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            print("[+] 서버에 연결 중...")
            while True:
                try:
                    s.connect((HOST, PORT))
                    break
                except (ConnectionRefusedError, OSError):
                    time.sleep(1)
            # 필요시 작은 패킷도 즉시 보내고 싶으면 활성화
            s.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)

            # 수신 스레드 시작
            disconnected = threading.Event()
            t = threading.Thread(target=recv_loop, args=(s, disconnected), daemon=True)
            t.start()

            for hex in hex_str:
                payload = unhexlify(hex)
                s.sendall(payload)
                print(f"Sent({len(payload)}): {hex}")
                time.sleep(1)

            while not disconnected.is_set():
                time.sleep(0.1)  # 수신 스레드가 종료될 때까지 대기

            # while True:
            #     user = input("Input bytes: 00 00 00 00 ")
            #     b = "00 00 00 00 " + user
            #     payload = unhexlify(b)
            #     s.sendall(payload)
            #     print(f"Sent({len(payload)}): {b}")
            #     time.sleep(1)  # 원래 코드 유지 (불필요하면 제거 가능)
        # except (KeyboardInterrupt, EOFError):
        #     print("\n[+] 종료합니다.")
        # finally:
        #     try:
        #         s.shutdown(socket.SHUT_RDWR)
        #     except Exception:
        #         pass
        #     # with 블록을 벗어나면 소켓 close

if __name__ == "__main__":
    main()
