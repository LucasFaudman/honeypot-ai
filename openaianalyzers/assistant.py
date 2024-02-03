from analyzerbase import *
from .aibase import *
from typing import Union
from osintanalyzers.ipanalyzer import IPAnalyzer
from osintanalyzers.malwareanalyzer import MalwareAnalyzer



class RunStatusError(Exception):
    """Run status is cancelled, failed, or expired"""

class RateLimitError(Exception):
    """OpenAI API rate limit reached"""


class OpenAIAssistantAnalyzer(OpenAIAnalyzerBase):
    """OpenAIAnalyzer based on Assistant API using GPT functions/tool_calls to update thread context window"""
    
    def __init__(self, 
                 db_path=Path("tests/aidb"), 
                 training_data_path=Path("openai-training-data"), 
                 api_key="<OPENAI_API_KEY>", 
                 model="gpt-4-1106-preview",
                 ip_analyzer: Union[IPAnalyzer, None]=None,
                 malwareanalyzer: Union[MalwareAnalyzer, None]=None,
                 honeypot_details={
                    "internal_ips": [],
                    "external_ips": [],
                    "ports": {},
                 },
                 use_code_interpreter=False,
                 ) -> None:
        super().__init__(db_path, training_data_path, api_key, model)
        # Make dir to store data for assistants    
        self.ai_assistants_dir = self.db_path / "assistants"
        if not self.ai_assistants_dir.exists():
            self.ai_assistants_dir.mkdir(exist_ok=True, parents=True)
        

        # To store Assistants, Threads, Runs, and Message Objects by id
        self.ai_assistants = {}
        self.ai_threads = {}
        self.ai_messages = {}
        self.ai_runs = {}


        # To handle tool calls (See _do_tool_call and tools.py)
        self.ip_analyzer = ip_analyzer
        self.malwareanalyzer = malwareanalyzer

        # To update system_prompt/instructions and tools
        self.honeypot_details = honeypot_details
        self.use_code_interpreter = use_code_interpreter
    

    def create_assistant(self, **kwargs):
        """Creates an assistant and stores it in ai_assistants dict and ai_assistants_dir/assistant_ids.txt"""

        assistant = self.client.beta.assistants.create(
            model = kwargs.pop("model", self.model),
            **kwargs,
        )
        
        with (self.ai_assistants_dir / "assistant_ids.txt").open("a+") as f:
            f.write(assistant.id + '\n')
        
        self.ai_assistants[assistant.id] = assistant
        return assistant
    

    def create_thread(self):
        """Creates a thread and stores it in ai_threads dict and ai_assistants_dir/thread_ids.txt"""

        thread = self.client.beta.threads.create()
        
        with (self.ai_assistants_dir / "thread_ids.txt").open("a+") as f:
            f.write(thread.id + '\n')


        self.ai_threads[thread.id] = thread
        return thread
    
    
    def create_run(self, ass_id, thread_id, **kwargs):
        """Creates a run and stores it in ai_runs dict and ai_assistants_dir/run_ids.txt"""
        
        run = self.client.beta.threads.runs.create(
                assistant_id=ass_id,
                thread_id=thread_id,
                **kwargs
        )

        with (self.ai_assistants_dir / "run_ids.txt").open("a+") as f:
            f.write(run.id + '\n')
        
        self.ai_runs[run.id] = run
        return run
    

    def get_assistant(self, ass_id):
        """Gets assistant from self or openai client if not retrieved yet"""
        assistant = self.ai_assistants.get(ass_id)
        
        if not assistant:
            assistant = self.client.beta.assistants.retrieve(ass_id)
            self.ai_assistants[assistant.id] = assistant

        return assistant


    def get_thread(self, thread_id):
        """Gets thread from self or openai client if not retrieved yet"""
        thread = self.ai_threads.get(thread_id)
        
        if not thread:
            thread = self.client.beta.threads.retrieve(thread_id)
            self.ai_threads[thread_id] = thread

        return thread


    def update_assistant(self, ass_id, **kwargs):
        """Updates Assistant system_prompt/instructions and/or functions/tools"""
        assistant = self.client.beta.assistants.update(
                        ass_id, **kwargs)

        return assistant
    

    def add_message_to_thread(self, content, thread_id):
        """Add content to therad as user message"""

        role = "user"
        message = self.client.beta.threads.messages.create(
            thread_id=thread_id,
            content=content,
            role=role
            
            )
        return message
    

    def wait_for_response(self, thread_id, run_id, attack, sleep_interval=5, **kwargs):
        """
        Waits for a response and handles status updates. 
        Calls handle_submit_tool_outputs_required to submit tool outputs when run requires action.
        Returns messages once recursive loop is complete. 
        """
        run = None
        while not run or run.status in ("queued", "in_progress"):
            run = self.client.beta.threads.runs.retrieve(
                        thread_id=thread_id,
                        run_id=run_id
                        )
            
            print(f"Status: {run.status} Thread id: {thread_id}, run_id: {run_id}")

            if run.status == "requires_action":
                # Handles tool calls and submits tool outputs to run then recursively calls wait_for_response
                return self.handle_submit_tool_outputs_required(run, attack, sleep_interval, **kwargs)

            elif run.status in ("cancelled", 'failed', 'expired'):
                raise RunStatusError(run.status, run.last_error)
            
            elif run.status == "completed":
                print(f"Run {run.id} completed")
                break

            else:
                print(f"Waiting {sleep_interval} seconds for response")
                sleep(sleep_interval)
        

        return self.client.beta.threads.messages.list(thread_id)
        
    
    def handle_submit_tool_outputs_required(self, run, attack, sleep_interval=5, **kwargs):
        """Executes tool calls and submits tool outputs to run."""

        tool_outputs=[]
        for tool_call in run.required_action.submit_tool_outputs.tool_calls:
            tool_name = tool_call.function.name
            arguments = json.loads(tool_call.function.arguments)

            print(f'\nAI called tool: {tool_name}\nwith args: {arguments}')
            # Get tool output with _do_tool_call
            tool_output = self._do_tool_call(tool_name, arguments, attack, **kwargs)
            
            print(f'\nSubmitting tool output: {tool_output}')
            
            # Format tool output and add to tool_outputs list
            tool_outputs.append({
                "tool_call_id": tool_call.id,
                "output":  self.format_content(tool_output)
            })


        # Submit tool outputs to run and get updated run
        run = self.client.beta.threads.runs.submit_tool_outputs(
                thread_id=run.thread_id,
                run_id=run.id,
                tool_outputs=tool_outputs
                )

        # Recursively call wait_for_response to handle next required_action        
        return self.wait_for_response(run.thread_id, run.id, attack, sleep_interval, **kwargs)
    

    def _do_tool_call(self, tool_name, arguments, attack, **kwargs):
        """Calls tool and returns output"""

        tool_output = {}
        
        # Sets tool_output to dict of {attr: attack.<attr>} for each attr in arguments["attrs"]         
        if tool_name == "get_attack_attrs":
            tool_output = {
                attr: getattr(attack, attr) for attr in arguments["attrs"]
            }
        
        # Get Session object by id and sets tool_output to dict of {attr: session.<attr>} for each attr in arguments["attrs"]
        elif tool_name == "get_session_attrs":
            session = attack.get_session_by_id(arguments['session_id'])
            tool_output = {
                attr: getattr(session, attr) if not attr.endswith("_time") 
                    else getattr(session, attr).strftime("%Y-%m-%d %H:%M:%S") 
                        for attr in arguments["attrs"]
            }

        # Gets Malware object by id and sets tool_output to dict of {attr: malware.<attr>} for each attr in arguments["attrs"]
        elif tool_name == "get_malware_attrs":
            malware = attack.get_malware_by_id(arguments['malware_id'])
            tool_output = {
                attr: getattr(malware, attr) for attr in arguments["attrs"]
            }

        # Sets tool_output to reduced ipdata from sources in arguments["sources"] for each ip in arguments["ips"] 
        elif tool_name == "query_ip_data" and self.ip_analyzer:
            # Uses IPAnalyzer to get data for ips from sources
            tool_output = self.ip_analyzer.get_reduced_data(
                arguments["ips"],
                "ip",
                arguments["sources"]
            )
            
        # Sets tool_output to reduced iocdata from sources in arguments["sources"] for each ioc in arguments["iocs"]
        elif tool_name == "query_ioc_data" and self.malwareanalyzer:
            # Uses MalwareAnalyzer to get data for iocs from sources
            tool_output = self.malwareanalyzer.get_reduced_data(
                arguments["iocs"],
                arguments["ioc_type"],
                arguments["sources"]
            )

        # Sets tool_output Malpedia result for malware with malpedia_name 
        elif tool_name == "query_malpedia" and self.malwareanalyzer:
            # Uses MalwareAnalyzer to get Malpedia data for malware with malpedia_name
            tool_output = self.malwareanalyzer.get_reduced_data(
                [arguments.get("malpedia_name", arguments.get("malware_name", "error")), ],
                "malpedia_name",
                ["malpedia"]
            )

        # Sets tool_output to ExploitDB search result for search_text
        elif tool_name == "search_exploitdb" and self.malwareanalyzer:
            # Uses MalwareAnalyzer to get ExploitDB results for search_text
            tool_output = self.malwareanalyzer.get_reduced_data(
                args=[arguments.get("search_text", arguments.get("text", "error")), ],
                arg_type="search_text",
                sources=["exploitdb"]
            )

        # Sets tool_output to ExploitDB exploit result for exploit_id
        elif tool_name == "get_exploitdb_exploit" and self.malwareanalyzer:
            # Uses MalwareAnalyzer to get ExploitDB exploit for exploit_id
            tool_output = self.malwareanalyzer.get_reduced_data(
                args=[arguments.get("exploit_id", arguments.get("id", "error")), ],
                arg_type="exploitdb_id",
                sources=["exploitdb"]
            )


        return tool_output


    def run_with_assistant(self, 
                           *content, 
                           ass_id=None, 
                           thread_id=None, 
                           system_prompt=None, 
                           tools=[], 
                           attack=None,
                           sleep_interval=5,
                           run_status_error_retries=1,
                           **kwargs                   
                           ):
        
        """Runs prompt with Assistant, handles tool_calls and returns Assistant, Thread, Run, Messages"""

        # Get or create Assistant and Thread
        ass = self.get_assistant(ass_id) if ass_id else self.create_assistant()
        thread = self.get_thread(thread_id) if thread_id else self.create_thread()


        # To determine if Assitant needs to be updated when system_prompt or tools have changed
        update_kwargs = {}
        # Check if model has changed
        if self.model != ass.model:
            update_kwargs.update({"model": self.model})
        # Check if system_prompt/instructions have changed
        if system_prompt != ass.instructions:
            update_kwargs.update({"instructions": system_prompt})
        # Check for different tool names in tools argument and Assitants current tools
        if tools != [tool.model_dump() for tool in ass.tools]:
            update_kwargs.update({"tools": tools})

        # Update Assitant if any update kwargs are present
        if update_kwargs:
            ass = self.update_assistant(ass.id, **update_kwargs)
            print(f"Updated {ass.id}: {', '.join(update_kwargs.keys())}")

        # Add content to thread as message(s)
        for message in content:
            self.add_message_to_thread(message, thread.id)

        # Create a run using the updated Assistant and Thread  
        run = self.create_run(ass.id, thread.id, **kwargs)


        # Wait for messages and recursively handle tool_calls until run is complete or RunStatusError occurs
        try:
            messages = self.wait_for_response(thread.id, run.id, attack, sleep_interval, **kwargs)
            
            print(f"Done {ass.id}, {thread.id}, {run.id}")
            return ass, thread, run, messages 
        
        except RunStatusError as e:
            print(e)
            
            if run_status_error_retries > 0:
                print(f"Retrying {run_status_error_retries} more time(s)")
                
                return self.run_with_assistant(content, ass_id, thread_id, system_prompt,
                                               tools, attack, sleep_interval,
                                               run_status_error_retries - 1, # Decrement retries 
                                               **kwargs)
            
            else:
                raise e # Raise the RunStatusError if no more retries 


    def read_or_init_attack_assistant(self):
        ass_id_file = self.ai_assistants_dir / "assistant_ids.txt"
        if ass_id_file.exists():
            with ass_id_file.open("r") as f:
                ass_id = f.readline().strip()
        else:
            ass_id = self.create_assistant().id
        
        return ass_id
    

    def read_or_init_attack_thread(self, attack):
        attack_thread_id_file = attack.attack_dir / "thread_id.txt"
        if attack_thread_id_file.exists():
            with attack_thread_id_file.open("r") as f:
                thread_id = f.readline().strip()
        else:
            thread_id = self.create_thread().id
            with attack_thread_id_file.open("a+") as f:
                f.write(thread_id + '\n')
        
        return thread_id


    def answer_attack_questions(self, questions, attack: Attack, interactive_chat=False):
        
        system_prompt = ''.join([
        "Your role is to answer questions about an attack on a Linux honeypot. "
        "You will analyze the commands executed, uploaded/downloaded files, HTTP requests, sessions"
        "and other data logged during the attack to understand the methods and goals of the attacker." 
        "You will also analyze OSINT data gathered about the attacking IP(s) including: geolocation, open ports, running services, "
        "threatfeed reports and reports of known malware associated with the IP(s) to get additional context on the attack and enhance your analysis. "
        "Your answers will be used in a GitHub .md file so you should use markdown syntax to format your output. "
        "Use the available functions to request relevant information to thoroughly answer each question. "
        "You should use multiple function calls to analyze the data returned by previous function calls "
        "and to get any additional data you need to answer each question as accurately as possible. "
        "For example if you see that the attacker downloaded malware in one of the commands executed, "
        "you should use the get_attack_attrs function with the arguement 'uniq_malware' to get a list of unique malware_ids associated with the attack, "
        "then use get_malware_attrs to analyze the malware, and the query_ functions to get additional OSINT data about the malware and its source. "
        "IMPORTANT: When using get_attack_attrs use the uniq_<attr> modifier first "
        "and only get all values if necessary after analyzing the unique values. "
        "For context that the honeypot system has the following open ports: ",
        ''.join(f'Port {port}: {software} ' for port, software in self.honeypot_details["ports"].items() if port in attack.uniq_dst_ports),
        f" Its internal IP address is: {','.join(self.honeypot_details['internal_ips'])} "
        f"and its external IP address is: {','.join(self.honeypot_details['external_ips'])}. "
        ])


        # Function schemas for Assistant tool_calls. See tools.py
        tools = list(TOOLS)

        # Add code_interpreter tool if use_code_interpreter is True.
        if self.use_code_interpreter:
            tools.append({"type": "code_interpreter"})
            system_prompt += ''.join([
            "Use the code_interpreter tool to enhance your analysis. ",
            "For example if you find an encoded string in the http_requests, commands, or malware, "
            "you should use the code_interpreter tool to decode it, then analyze the decoded result in context "
            "when answering questions."
            ])


        # Make a dir to store answers to questions for Attack
        # Use assistants_dir in aidb when runnning in standard mode and attack_dir/ai-chat when running in interactive_chat mode
        if not interactive_chat:
            attack_questions_dir = self.ai_assistants_dir / attack.attack_id
        else:
            attack_questions_dir = attack.attack_dir / "ai-chat"

        attack_questions_dir.mkdir(exist_ok=True, parents=True)

        # Get or create Assistant and Thread for the Attack.
        # Reusing the same Thread is critical for the Assistant to be able to use context from previous questions to answer new questions.
        ass_id = self.read_or_init_attack_assistant()
        thread_id = self.read_or_init_attack_thread(attack)

        question_run_logs = {}
        # Iter through questions and get answer for each question
        for question_key, question in questions.items():

            # Filename for saving answer is the question_key and is saved in the attack directory
            question_answer_file = attack_questions_dir / (question_key + '.json')
            
            # Use stored answer if answer file exists
            if question_answer_file.exists():
                with question_answer_file.open("r") as f:
                    question_run_log = json.load(f)
                    question_run_logs[question_key] = question_run_log
                
                continue # Prevent wasting tokens by asking question again

            
            print(f"\n\nAsking: {question}")
            # Run with assistant with question as content
            ass, thread, run, messages = self.run_with_assistant(
                question,
                ass_id=ass_id,
                thread_id=thread_id,
                system_prompt=system_prompt,
                tools=tools,
                attack=attack,
                )
            
            # Assign values if Assitant or thread was newly created
            ass_id = ass.id
            thread_id = thread.id
            run_id = run.id

            # Answer is latest message in Thread
            answer = messages.data[0].content[0].text.value

            # Retreive run steps in ascending order            
            run_steps = self.client.beta.threads.runs.steps.list(
                run_id=run_id,
                thread_id=thread_id,
                limit=100,
                order="asc"
                )
            
            question_run_log = {
                "model": self.model,
                "question_key": question_key,
                "content": question,
                "answer": answer,
                "system_prompt": system_prompt,
                "ass_id": ass_id,
                "thread_id": thread_id,
                "run_id": run_id,
                "run_steps": run_steps.model_dump(),
            }
            
            question_run_logs[question_key] = question_run_log

            with question_answer_file.open("w+") as f:
                json.dump(question_run_log, f, indent=4)
            
            print(f"\n Done with: {question}\nAnswer: {answer}")

        return question_run_logs
        

    def interactive_chat_about_attack(self, attack):
        print(f"\nEntering Chat Mode.\nAsk the AI assistant custom questions about:\n{attack}")
        question_run_logs = {}
        question_to_ask = {}

        question_num = max(
            [int(qfile.name.split("_")[1].replace(".json", ""))
             for qfile in (attack.attack_dir / "ai-chat").glob("question_*.json")]
            + [0]
        ) + 1  # Start at 1 or highest question number +1 if previous chats

        choice = ""
        quit_strings = ("q", "quit", "exit", "exit()")
        while choice not in quit_strings:
            msg = f"\nAI Interactive Chat\n{attack}\n"
            msg += "\nCurrent questions:\n" 
            msg += pprint_str(question_to_ask)
            msg += "\nChoices:"
            msg += "\n a) Ask questions"
            msg += "\n e) Enter a question"
            msg += "\n u) Upload multiline question from file"
            msg += "\n c) Clear questions"
            msg += f"\n m) Change OpenAI model. (Current model: {self.model})"
            msg += "\n p) Print attack attributes"
            msg += "\n q) Quit and continue main"
            msg += "\n\nEnter choice (a, e, u, c, m, p OR q): "
            choice = input(msg)
            choice = choice.lower().strip()[0] if choice else ""

            if choice == "e":
                question = input("Enter question: ")
                question_key = f"question_{question_num}"
                question_key = input(f"Enter question key or leave empty to use '{question_key}' : ").replace(' ', '_').replace('/', '_') or question_key
                question_to_ask[question_key] = question
                question_num += 1
            
            elif choice == "u":
                question_file = input("Enter question file path: ")
                question_key = f"question_{question_num}"
                question_key = input(f"Enter question key or leave empty to use '{question_key}' : ").replace(' ', '_').replace('/', '_') or question_key
                if not Path(question_file).exists():
                    print(f"ERROR: File {question_file} does not exist.")
                    continue
                
                with Path(question_file).open("r") as f:
                    question_to_ask[question_key] = f.read()
                    question_num += 1
                    
            elif choice == "a":
                question_run_logs.update(self.answer_attack_questions(question_to_ask, attack, interactive_chat=True))
                question_to_ask = {}
            
            elif choice == "c":
                question_to_ask = {}

            elif choice == "p":
                # Get valid attack attributes to pprint
                attrs = set(input("Enter attack attribute to pprint: ").split()) & set(dir(attack))
                attack.print_attrs(attrs)
            
            elif choice == "m":
                new_model = input("Enter new OpenAI model: ")
                if new_model:
                    self.set_model(new_model)
                    
            elif choice not in quit_strings:
                print("\nInvalid choice. Try again.")
                sleep(1)
        
        
        return question_run_logs

