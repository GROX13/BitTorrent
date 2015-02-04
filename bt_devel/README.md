# Skeleton development for BitTorrent (BT) client. 

Included Files and Purpose

bt_client.c   :   Main file where the control loop lives
bt_setup.c    :   Contains setup code, such as parsing arguments
bencode.c     :   Code for parsing bencoded torrent files
bt_sock.c     :   File for handling socket and network issues
bt_lib.c      :   Code for core functionality of bt
bt_io.c       :   File for handing input output

bt_setup.h    :   Header file for setup
bencode.h     :   Header file for bencode
bt_sock.h     :   Header file for bt_sock
bt_lib.h      :   Header file for bt_lib
bt_io.h       :   Header file for bt_io
