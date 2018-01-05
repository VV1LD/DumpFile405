# DumpFile405
File Decrypter for the PS4 version 4.05

change your ip address to use the pc you are listening ie:
  socat - tcp-listen:9023

compile with IDC's Cturt SDK mod ps4-payload-sdk https://github.com/idc/ps4-payload-sdk

-on your usb stick (fat32) make a directory /405
-insert into the ps4 and run the payload

This will dump all the usermodules self/sprx/sdll/sexe onto your usb in the /405 folder decrypted
some like eboots are renamed because i was too lazy to implement folder generation to mimic the ps4 fs
but you can change to code to suit whatever you choose to :)

=Credits=
-Specter for his kernel exploit / code execution method / syscall 11 which makes this easy
-IDC for his mode of the Cturt SDK and his patches to allow for self decryption
-Grass Skeu for the original code base this was made from (DumpFile for 1.76 built for hitodamas ps4sdk)
