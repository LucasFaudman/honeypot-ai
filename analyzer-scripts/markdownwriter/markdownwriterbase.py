from analyzerbase import *



nomd = lambda text: f'{text}' #Gets fstring of object for sytle_fn default 
placeholder = nomd #Does nothing just used for debugging CTRL-D replacement

h1 = lambda text: f'\n# {text}\n'
h2 = lambda text: f'\n## {text}\n'
h3 = lambda text: f'\n### {text}\n'
h4 = lambda text: f'\n#### {text}\n'
hline = lambda: '\n---\n'

italic = lambda text: f'*{text}*'
bold = lambda text: f'**{text}**'
link = lambda text, url: f'[{text}](' + url + ')'
image = lambda text, url: f'![{text}](' + url + ')'
code = lambda text: f'`{text}`'
codeblock = lambda text, lang="": f'\n```{lang}\n{text}\n```\n'
blockquote = lambda text: f'> {text}\n'
bullet = lambda text: f'* {text}\n'
blockbullet = lambda text: f'> * {text}\n'

unordered_list = lambda items, style_fn=nomd: ''.join([f'\n* {style_fn(item)}' for item in items]) + '\n\n'
ordered_list = lambda items, style_fn=nomd: ''.join([f'\n{n}. {style_fn(item)}\n' for n,item in enumerate(items)]) + '\n\n'
collapsed = lambda text, summary="", style_fn=nomd: f'<details>{text}<summary>{style_fn(summary)}</summary></details>'


def collapseable_section(text, label, header_level=2, blockquote=False):
    bqstart = '\n<blockquote>' if blockquote else ''
    bqend = '</blockquote>\n' if blockquote else ''
    section_md = f"""{bqstart}
<details>
<summary>
<h{str(header_level)}>{label}</h{str(header_level)}>
</summary>

{text}
</details>
{bqend}
---

"""

    return section_md



def nested_list(items, style_fn=nomd, depth=0, style_dict={}):
    
    
    for i,item in enumerate(items):
        
        if isinstance(item, (list, tuple, set)):
            items[i] = nested_list(item, style_fn, depth+1, style_dict)
        
        else:
            indent = '\t' * depth
            bullet_char = '-' if depth >= 0 else ''            
            items[i] = f'\n{indent}{bullet_char} {style_dict.get(depth, style_fn)(item)}'

    
    return ''.join(items) + '\n'


def md_join(items, style_fn=nomd, sep=', '):
    if callable(style_fn):
        return sep.join([style_fn(item) for item in items])
    elif len(style_fn) == len(items):
        return sep.join([style_fn[i](item) for i,item in enumerate(items)])
    else:
        return sep.join(items)



def table(headers, rows, style_fn=nomd, alignments=[]):
    table_md = '\n'
    table_md += '| ' + ' | '.join(nomd(header).replace('|',r'\|') for header in headers) + ' |\n'

    alignment_strs = {"left": ":---", "right": "---:", "center": ":---:"}
    # Allow ('l', 'r', 'c') as valid alignment values
    alignment_strs.update({k[0]: v for k,v in alignment_strs.items()})

    # Add alignment row
    if len(alignments) == len(headers):
        alignments = [alignment_strs.get(alignment, "---") for alignment in alignments]
        table_md += '| ' + ' | '.join(alignments) + ' |\n'
    else:
        table_md += '| ' + ' | '.join(['---' for _ in headers]) + ' |\n'
    

    for row in rows:
        row = [style_fn(nomd(item).replace('|',r'\|')) for item in row]
        table_md += '| ' + ' | '.join(row) + ' |\n'
    
    return table_md



def most_common_table(label, counter, n=10, style_fn=code, header_level=3, use_blockquote=False):
    if n > len(counter):
        n = len(counter)
    
    
    tabel_label = f"Top {n} {label.title() if not label.isupper() else label}" \
                    + ('s' if not label.endswith('s') else '')
    table_md = placeholder(f"Total {label}s: {code(sum(counter.values()))}\nUnique: {code(len(counter))}\n")
        
        
    headers = [label, "Times Seen"]
    if isinstance(label, (tuple, list)):
        headers = label[:2]

    table_md += table(headers, [(item, count) for item, count in counter.most_common(n)], style_fn)
    md = collapseable_section(table_md, tabel_label, header_level, use_blockquote)

    return md



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
    

