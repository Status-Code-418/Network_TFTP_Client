#  Network_TFTP_Client

###  [ TFTP Client Python Code ]

▷  OS
  - Windows

▷  SoftWare
  - Python3
  - TFTP Client

###  [ Python Code(Program) Command ]

▷  baseline) python3 [TFTP Client Code file] [host] [options(get|put)] [file name]
  - python3 TFTP_Client.py 192.168.0.1 get abcd.txt
 
▷  baseline) python3 [TFTP Client Code file] [host] [-port] [options(get|put)] [file name]
  - python3 TFTP_Client.py 192.168.0.1 -p 9988 get abcd.txt

▷  ex)
  - python3 TFTP_Client.py 192.168.0.1 get abcd.txt
  - python3 TFTP_Client.py 192.168.0.1 put abcd.txt

  - python3 TFTP_Client.py 192.168.0.1 -p 9988 get abcd.txt
  - python3 TFTP_Client.py 192.168.0.1 -p 9988 put abcd.txt

###  [ TFTP Server Setting ]
▷  Server install command
  - sudo apt install tftpd-hpa

▷  Server conf file
  - sudo nano /etc/default/tftpd-hpa

    TFTP_USERNAME="tftp"  
    TFTP_DIRECTORY="/tftpboot"  
    TFTP_ADDRESS="0.0.0.0:69"  
    TFTP_OPTIONS="--secure --create"
  
▷  Server status check command
  - sudo systemctl status tftpd-hpa

▷  Server start command
  - sudo systemctl start tftpd-hpa

▷  Server enable command
  - sudo systemctl enable tftpd-hpa

▷  Server restart command
  - sudo systemctl restart tftpd-hpa

▷  Server stop command
  - sudo systemctl stop tftpd-hpa

▷  Server disable command
  - sudo systemctl disable tftpd-hpa
