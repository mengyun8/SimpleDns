# SimpleDns
 Simple Dns Server

Use Command test:

#dig @127.0.0.1 www.test.com 
; <<>> DiG 9.11.0-P3 <<>> @127.0.0.1 xxx.test.com
; (1 server found)
;; global options: +cmd
;; Got answer:
;; ->>HEADER<<- opcode: QUERY, status: NOERROR, id: 12498
;; flags: qr; QUERY: 1, ANSWER: 2, AUTHORITY: 0, ADDITIONAL: 0

;; QUESTION SECTION:
;xxx.test.com.			IN	A

;; ANSWER SECTION:
xxx.test.com.		600	IN	CNAME	aaa.test.com.
aaa.test.com.		200	IN	A	1.2.3.4

;; Query time: 0 msec
;; SERVER: 127.0.0.1#53(127.0.0.1)
;; WHEN: Tue Sep 05 01:09:45 PDT 2017
;; MSG SIZE  rcvd: 96

