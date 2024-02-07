from .markdownwriterbase import *


class RunStepsMarkdownWriter(MarkdownWriterBase):
    """
    Markdown writer for AI RunSteps for questions asked by the OpenAIAssistantAnalyzer when processed by the AttackAnalyzer
    and when in interactive mode. 
    """

    def prepare(self):
        attack = self.data_object
        self.md += h1("Run Steps: " + attack.answers.get("title",
                      f"Attack: {attack.attack_id}").strip('"'))
        self.md_editors.append(self.add_question_run_logs)

    def add_question_run_logs(self, md, attack: Attack):
        sorted_run_logs = sorted(attack.question_run_logs.values(),
                                 key=lambda run_log: run_log["run_steps"].get(
                                     "data", [{"created_at": 0}])[0]["created_at"]
                                 )

        for n, run_log in enumerate(sorted_run_logs):
            if n == 0:
                md += f"{bold('Assistant ID:')} {code(run_log['ass_id'])}\n\n"
                md += f"{bold('Thread ID:')} {code(run_log['thread_id'])}\n\n"
                md += collapseable_section(blockquote(
                    code(run_log["system_prompt"])), "System Prompt", 3)

            md += self.make_question_run_log_md(run_log)

        return md

    def make_question_run_log_md(self, run_log):

        question_md = h2(f"Prompt: {run_log['content']}") + '\n'
        question_md += f"{bold('Run ID:')} {code(run_log['run_id'])}\n"

        tool_call_steps = [step for step in run_log["run_steps"]
                           ["data"] if step.get('type') == 'tool_calls']
        if tool_call_steps:
            question_md += h3("Funciton Calls")
            for step in tool_call_steps:
                question_md += f"{bold('Step ID:')} {code(step['id'])}\n"

                for tool_call in step["step_details"]["tool_calls"]:
                    if tool_call.get("function"):
                        question_md += f"\n{bold('Function called:')} {code(tool_call['function']['name'])}\n"
                        arguments = json.loads(
                            tool_call["function"]["arguments"])
                        output = json.loads(tool_call["function"]["output"])
                        question_md += table(["Argument", "Value"], [(code(arg), code(value))
                                             for arg, value in arguments.items()])
                        question_md += table(["Output", "Value"], [(code(arg), code(value))
                                             for arg, value in output.items()])
                    elif tool_call.get("code_interpreter"):
                        question_md += f"\n{bold('AI Used: Code Interpreter')}\n"
                        question_md += h4("Input Code:")
                        question_md += codeblock(
                            tool_call["code_interpreter"]["input"], "python")
                        question_md += h4("Outputs:")
                        for output_dict in tool_call["code_interpreter"]["outputs"]:
                            for key, output in output_dict.items():
                                if key == "type":
                                    continue
                                question_md += codeblock(output, "python")
                    else:
                        question_md += f"{bold('No function or code interpreter called')}\n"

                    question_md += "\n"

        question_md += collapseable_section(run_log["answer"], "Answer", 3)

        return question_md
