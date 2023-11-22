from analyzerbase import *





h1 = lambda text: f'# {text}\n'
h2 = lambda text: f'## {text}\n'
h3 = lambda text: f'### {text}\n'
h4 = lambda text: f'#### {text}\n'
italic = lambda text: f'*{text}*'
bold = lambda text: f'**{text}**'
link = lambda text, url: f'[{text}](' + url + ')'
image = lambda text, url: f'![{text}](' + url + ')'
code = lambda text: f'`{text}`'
codeblock = lambda text, lang="": f'\n```{lang}\n{text}\n```\n'
blockquote = lambda text: f'> {text}\n'
bullet = lambda text: f'* {text}\n'
blockbullet = lambda text: f'> * {text}\n'
unordered_list = lambda items, style_fn=str: ''.join([f'\n* {style_fn(item)}' for item in items]) + '\n'
ordered_list = lambda items, style_fn=str: ''.join([f'\n{n}. {style_fn(item)}\n' for n,item in enumerate(items)]) + '\n'
hline = lambda: '---\n'
collapsed = lambda text, summary="", style_fn=str: f'<details>\n<summary>{style_fn(summary)}</summary>\n{text}\n</details>\n'



def table(headers, rows, style_fn=str, alignments=[]):
    table = ''
    table += '| ' + ' | '.join(str(header).replace('|',r'\|') for header in headers) + ' |\n'

    alignment_strs = {"left": ":---", "right": "---:", "center": ":---:"}
    # Allow ('l', 'r', 'c') as valid alignment values
    alignment_strs.update({k[0]: v for k,v in alignment_strs.items()})

    # Add alignment row
    if len(alignments) == len(headers):
        alignments = [alignment_strs.get(alignment, "---") for alignment in alignments]
        table += '| ' + ' | '.join(alignments) + ' |\n'
    else:
        table += '| ' + ' | '.join(['---' for _ in headers]) + ' |\n'
    

    for row in rows:
        row = [style_fn(str(item).replace('|',r'\|')) for item in row]
        table += '| ' + ' | '.join(row) + ' |\n'
    return table


def collapseable_section(text, label, header_level=2, blockquote=True):
    return f"""{'<blockquote>' if blockquote else ''}
<details>
<summary>
<strong><h{str(header_level)}>{label}</h{str(header_level)}>

</strong></summary>

{text}

</details>
{'</blockquote>' if blockquote else ''}"""


def convert_md_to_mdtxt_for_canvas(filepath, github_url):
    txt_header = f"""NOTE: This is a .md file with GitHub formatting. 
If you are viewing this in Canvas, please click the following link to view the formatted file on GitHub: 
{github_url}
Alternatively, you can download the file and view it locally in your IDE.
All relevant logs and scripts can also be found in this repository.
""" 
    with open(filepath, 'r') as f:
        md = f.read()
    with open(filepath.replace('.md', '.md.txt'), 'w+') as f:
        f.write(txt_header)
        f.write('\n\n')
        f.write(md)




class MarkdownWriter:
    def __init__(self, filepath="test.md", mode="a+", md="", data_object: Union[dict, Attack]={}):
        
        self.filepath = Path(filepath)
        self.mode = mode
        self.md = md
        self.data_object = data_object
        
        self.md_editors = []
        

    def edit_md(self, md, data_object={}):
        for editor in self.md_editors:
            md = editor(md, data_object)
        return md

    def update_md(self):
        self.prepare()
        self.md = self.edit_md(self.md, self.data_object)
        self.write_md(self.md)

    def write_md(self, md):
        with self.filepath.open(self.mode) as f:
            f.write(md)
    
    def prepare(self):
        #Implement in subclasses
        return NotImplementedError