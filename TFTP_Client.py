#!/usr/bin/python3
'''
TFTP 클라이언트 프로그램

사용법 예시(명령어 구문):
$ python3 [tftp client 코드] host [-p port] [get|put] filename

예시:
   $ python TFTP_Client.py 192.168.1.197 get abcd.txt
   $ python TFTP_Client.py 192.168.1.197 put abcd.txt
   $ python TFTP_Client.py 192.168.1.197 -p 9988 get abcd.txt
'''

# 호출 라이브러리 목록
import socket       # 통신 소켓
import argparse     # commandline 인자 파싱
import sys          # 시스템 함수(종료)
import os           # 파일 시스템(파일 존재 여부 확인)
from struct import pack, unpack # 바이트 데이터 패킷 생성 및 파싱


# --- TFTP 프로토콜 상수 정의 ---
DEFAULT_PORT = 69
BLOCK_SIZE = 512
DEFAULT_TRANSFER_MODE = 'octet'
TIME_OUT = 2 # 소켓 타임아웃 시간 (초)
MAX_TRY = 5  # 최대 재전송 시도 횟수

# TFTP Opcode (작업 코드)
OPCODE = {'RRQ': 1, 'WRQ': 2, 'DATA': 3, 'ACK': 4, 'ERROR': 5}
# TFTP 전송 모드
MODE = {'netascii': 1, 'octet': 2, 'mail': 3}

# TFTP 에러 코드
ERROR_CODE = {
    0: "Not defined, see error message (if any).",
    1: "File not found.",
    2: "Access violation.",
    3: "Disk full or allocation exceeded.",
    4: "Illegal TFTP operation.",
    5: "Unknown transfer ID.",
    6: "File already exists.",
    7: "No such user."
}


# --- TFTP 패킷 전송 함수 ---

def send_wrq(sock_obj, filename_str, mode_str, remote_addr):
    # WRQ (Write Request) 패킷을 생성하여 서버에 전송한다.
    # 패킷 구조 : Opcode (2 bytes) + Filename (variable) + 0x00 + Mode (variable) + 0x00
    
    format_str = f'>h{len(filename_str)}sB{len(mode_str)}sB'
    wrq_packet = pack(format_str, OPCODE['WRQ'], bytes(filename_str, 'utf-8'), 0, bytes(mode_str, 'utf-8'), 0)
    sock_obj.sendto(wrq_packet, remote_addr)
    return wrq_packet


def send_rrq(sock_obj, filename_str, mode_str, remote_addr):
    # RRQ (Read Request) 패킷을 생성하여 서버에 전송한다.
    # 패킷 구조 : Opcode (2 bytes) + Filename (variable) + 0x00 + Mode (variable) + 0x00

    format_str = f'>h{len(filename_str)}sB{len(mode_str)}sB'
    rrq_packet = pack(format_str, OPCODE['RRQ'], bytes(filename_str, 'utf-8'), 0, bytes(mode_str, 'utf-8'), 0)
    sock_obj.sendto(rrq_packet, remote_addr)
    return rrq_packet


def send_ack(sock_obj, block_num, target_addr):
    # ACK (Acknowledgement) 패킷을 생성하여 특정 블록 번호에 대해 응답한다.
    # 패킷 구조 : Opcode (2 bytes) + Block Number (2 bytes)

    ack_packet = pack(f'>hh', OPCODE['ACK'], block_num)
    sock_obj.sendto(ack_packet, target_addr)
    

def handle_error_packet(error_data):
    # 서버로부터 수신한 ERROR 패킷을 처리하고 프로그램을 종료한다.

    error_code = unpack('>h', error_data[2:4])[0]
    error_message = error_data[4:-1].decode('utf-8', errors='ignore')
    print(f'ERROR: [{error_code}] {ERROR_CODE.get(error_code, "Unknown error.")} - {error_message}')
    sys.exit(1)


if __name__ == "__main__":

    # 1. commandline 인자 파싱
    parser = argparse.ArgumentParser(description='TFTP 클라이언트 프로그램.')
    parser.add_argument(dest="host", help="서버 IP 주소 또는 도메인 이름", type=str)
    parser.add_argument(dest="operation", help="get(다운로드) 또는 put(업로드)", type=str, choices=['get', 'put'])
    parser.add_argument(dest="filename", help="전송할 파일 이름", type=str)
    parser.add_argument("-p", "--port", dest="port", type=int, default=DEFAULT_PORT,
                        help=f"서버 포트 번호 (기본값: {DEFAULT_PORT})")
    args = parser.parse_args()


    # 2. 호스트명(도메인)을 IP 주소로 변환
    try:
        server_ip = socket.gethostbyname(args.host)
    except socket.gaierror:
        print(f"ERROR: '{args.host}' 호스트명을 IP 주소로 확인할 수 없습니다. 호스트명/IP 주소를 확인하십시오.")
        sys.exit(1)

    server_address = (server_ip, args.port)


    # 3. UDP 소켓 생성 및 타임아웃 설정
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(TIME_OUT)

    transfer_mode = DEFAULT_TRANSFER_MODE
    operation = args.operation
    target_filename = args.filename


    # GET (파일 다운로드) 구현
    if operation == 'get':
        if os.path.exists(target_filename):
            print(f"WARNING: 로컬에 '{target_filename}' 파일이 이미 존재합니다. 덮어쓰기 합니다.")

        # RRQ 패킷 전송
        initial_request_packet = send_rrq(sock, target_filename, transfer_mode, server_address)
        
        expected_block_number = 1
        last_acked_block_number = 0 # 마지막으로 성공적으로 ACK를 보낸 블록 번호
        current_server_transfer_address = None # 데이터 전송에 사용될 서버의 실제 주소 (TID)
        retries = 0

        try:
            with open(target_filename, 'wb') as file_obj:
                while True:
                    try:
                        data, sender_addr = sock.recvfrom(BLOCK_SIZE + 4)
                        retries = 0 # 수신 성공 시 재시도 횟수 초기화

                        # 데이터 전송에 사용되는 서버 주소 확인 (TID)
                        if current_server_transfer_address is None:
                            current_server_transfer_address = sender_addr
                        elif sender_addr != current_server_transfer_address:
                            print(f"WARNING: 예상치 못한 주소 ({sender_addr})로부터 패킷 수신. 무시합니다.")
                            continue

                    except socket.timeout:
                        if retries < MAX_TRY:
                            retries += 1
                            # 초기 요청 또는 이전 ACK 재전송
                            sock.sendto(initial_request_packet, server_address) # RRQ 재전송
                            continue
                        else:
                            print(f"ERROR: {MAX_TRY}회 재시도 후에도 응답이 없어 다운로드 실패.")
                            sys.exit(1)
                    except Exception as e:
                        print(f"ERROR: 데이터 수신 중 예외 발생: {e}")
                        sys.exit(1)

                    opcode = unpack('>h', data[:2])[0]
                    
                    if opcode == OPCODE['DATA']:
                        block_number = unpack('>h', data[2:4])[0]

                        if block_number == expected_block_number:
                            file_block_content = data[4:]
                            file_obj.write(file_block_content)
                            send_ack(sock, block_number, current_server_transfer_address)
                            last_acked_block_number = block_number
                            expected_block_number += 1
                            
                            # 마지막 블록 확인 (블록 크기가 BLOCK_SIZE 미만)
                            if len(file_block_content) < BLOCK_SIZE:
                                break
                        elif block_number == last_acked_block_number: # 중복 DATA 패킷 (ACK 손실)
                            send_ack(sock, last_acked_block_number, current_server_transfer_address)
                        else: # 예상치 못한 블록 번호 (이전 ACK 재전송 유도)
                            send_ack(sock, last_acked_block_number, current_server_transfer_address)

                    elif opcode == OPCODE['ERROR']:
                        handle_error_packet(data)
                    else:
                        print(f"ERROR: 알 수 없는 Opcode ({opcode}) 패킷 수신. 종료합니다.")
                        break
        except IOError as e:
            print(f"ERROR: 파일 '{target_filename}' 작업 중 오류 발생: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: 다운로드 중 예상치 못한 오류 발생: {e}")
            sys.exit(1)
    

    # PUT (파일 업로드) 구현
    elif operation == 'put':
        if not os.path.exists(target_filename):
            print(f"ERROR: 로컬에 '{target_filename}' 파일이 존재하지 않습니다. 경로를 확인하십시오.")
            sys.exit(1)

        file_obj = None # finally 블록에서 파일 객체를 닫기 위함
        # WRQ 패킷 전송
        initial_request_packet = send_wrq(sock, target_filename, transfer_mode, server_address)
        
        current_block_number = 0 # 현재 보낼 DATA 블록 번호 (WRQ ACK는 0번)
        current_server_transfer_address = None # ACK 수신 및 DATA 전송에 사용될 서버의 실제 주소 (TID)
        last_sent_data_packet = b'' # 재전송을 위한 마지막 DATA 패킷
        retries = 0

        try:
            file_obj = open(target_filename, 'rb')
            while True:
                try:
                    response, sender_addr = sock.recvfrom(BLOCK_SIZE + 4)
                    retries = 0 # 수신 성공 시 재시도 횟수 초기화

                    # ACK 전송에 사용되는 서버 주소 확인 (TID)
                    if current_server_transfer_address is None:
                        current_server_transfer_address = sender_addr
                    elif sender_addr != current_server_transfer_address:
                        print(f"WARNING: 예상치 못한 주소 ({sender_addr})로부터 패킷 수신. 무시합니다.")
                        continue

                except socket.timeout:
                    if retries < MAX_TRY:
                        retries += 1
                        # 초기 WRQ 또는 이전 DATA 패킷 재전송
                        if current_block_number == 0: # WRQ ACK 대기 중
                            sock.sendto(initial_request_packet, server_address) # WRQ 재전송
                        else: # DATA 패킷 ACK 대기 중
                            if last_sent_data_packet:
                                sock.sendto(last_sent_data_packet, current_server_transfer_address) # DATA 재전송
                        continue
                    else:
                        print(f"ERROR: {MAX_TRY}회 재시도 후에도 응답이 없어 업로드 실패.")
                        sys.exit(1)
                except Exception as e:
                    print(f"ERROR: 응답 수신 중 예외 발생: {e}")
                    sys.exit(1)

                opcode = unpack('>h', response[:2])[0]

                if opcode == OPCODE['ACK']:
                    acked_block_num = unpack('>h', response[2:4])[0]

                    if acked_block_num == current_block_number: # 예상한 ACK 블록 번호 일치
                        current_block_number += 1
                        file_block_data = file_obj.read(BLOCK_SIZE)

                        if not file_block_data: # 전송할 데이터가 없으면 전송 완료
                            break

                        # DATA 패킷 생성 및 전송
                        data_packet_to_send = pack(f'>hh{len(file_block_data)}s', OPCODE['DATA'], current_block_number, file_block_data)
                        sock.sendto(data_packet_to_send, current_server_transfer_address)
                        last_sent_data_packet = data_packet_to_send # 재전송을 위해 저장
                    else: # 예상치 못한 ACK 블록 번호 수신 (무시 또는 경고)
                        pass # 타임아웃 재전송 로직에 맡김
                
                elif opcode == OPCODE['ERROR']:
                    handle_error_packet(response)
                else:
                    print(f"ERROR: 알 수 없는 Opcode ({opcode}) 패킷 수신. 종료합니다.")
                    break

        except IOError as e:
            print(f"ERROR: 파일 '{target_filename}' 작업 중 오류 발생: {e}")
            sys.exit(1)
        except Exception as e:
            print(f"ERROR: 업로드 중 예상치 못한 오류 발생: {e}")
            sys.exit(1)
        finally:
            if file_obj and not file_obj.closed:
                file_obj.close()
    
    sock.close() # 소켓 종료
