from analyzerbase import *
from pathlib import Path
from urllib.parse import quote


class MarkdownWriterBase:
    """Base class for writing markdown files."""

    def __init__(self, filepath="test.md", mode="a+", md="", data_object={}):

        self.filepath = Path(filepath)
        self.mode = mode
        self.md = md
        self.data_object = data_object
        self.md_editors = []

    def prepare(self):
        # Implemented in subclasses
        return NotImplementedError

    def edit_md(self, md, data_object):
        for editor in self.md_editors:
            md = editor(md, data_object)
        return md

    def write_md(self, md):
        with self.filepath.open(self.mode) as f:
            f.write(md)

    def update_md(self):
        self.prepare()
        self.md = self.edit_md(self.md, self.data_object)
        self.write_md(self.md)


def nomd(text): return f'{text}'  # Gets fstring of object for sytle_fn default
def h1(text): return f'\n# {text}\n'
def h2(text): return f'\n## {text}\n'
def h3(text): return f'\n### {text}\n'
def h4(text): return f'\n#### {text}\n'
def hline(): return '\n---\n'
def italic(text): return f'*{text}*'
def bold(text): return f'**{text}**'
def link(text, url): return f'[{text}](' + url + ')'
def image(text, url): return f'![{text}](' + url + ')'
def code(text): return f'`{text}`'
def codeblock(text, lang=""): return f'\n````{lang}\n{text}\n````\n'
def blockquote(text): return f'> {text}\n'
def bullet(text): return f'* {text}\n'
def blockbullet(text): return f'> * {text}\n'


def md_join(items, style_fn=nomd, sep=', '):
    if callable(style_fn):
        return sep.join([style_fn(item) for item in items])
    elif len(style_fn) == len(items):
        return sep.join([style_fn[i](item) for i, item in enumerate(items)])
    else:
        return sep.join(items)


def unordered_list(items, style_fn=nomd): return ''.join(
    [f'\n* {style_fn(item)}' for item in items]) + '\n\n'


def ordered_list(items, style_fn=nomd): return ''.join(
    [f'\n{n}. {style_fn(item)}\n' for n, item in enumerate(items)]) + '\n\n'


def nested_list(items, style_fn=nomd, depth=0, style_dict={}):

    for i, item in enumerate(items):

        if isinstance(item, (list, tuple, set)):
            items[i] = nested_list(item, style_fn, depth+1, style_dict)

        else:
            indent = '\t' * depth
            bullet_char = '-' if depth >= 0 else ''
            items[i] = f'\n{indent}{bullet_char} {style_dict.get(depth, style_fn)(item)}'

    return ''.join(items) + '\n'


def collapsed(text, summary="", style_fn=nomd):
    return f'<details>{text}<summary>{style_fn(summary)}</summary></details>'


def collapseable_section(text, label, header_level=2, blockquote=False, end_line=True):
    bqstart = '\n<blockquote>' if blockquote else ''
    bqend = '</blockquote>\n' if blockquote else ''
    end_line = '---\n' if end_line else ''
    if header_level:
        hstart = f"<h{str(header_level)}>"
        hend = f"</h{str(header_level)}>"
    else:
        hstart = ''
        hend = ''

    section_md = f"""{bqstart}
<details>
<summary>
{hstart}{label}{hend}
</summary>

{text}
</details>
{bqend}
{end_line}
"""

    return section_md


def table(headers, rows, style_fn=nomd, alignments=[]):
    table_md = '\n'
    table_md += '| ' + ' | '.join(nomd(header).replace('|', r'\|')
                                  for header in headers) + ' |\n'

    alignment_strs = {"left": ":---", "right": "---:", "center": ":---:"}
    # Allow ('l', 'r', 'c') as valid alignment values
    alignment_strs.update({k[0]: v for k, v in alignment_strs.items()})

    # Add alignment row
    if len(alignments) == len(headers):
        alignments = [alignment_strs.get(alignment, "---")
                      for alignment in alignments]
        table_md += '| ' + ' | '.join(alignments) + ' |\n'
    else:
        table_md += '| ' + ' | '.join(['---' for _ in headers]) + ' |\n'

    for row in rows:
        row = [style_fn(nomd(item).replace('|', r'\|')) for item in row]
        table_md += '| ' + ' | '.join(row) + ' |\n'

    return table_md


def most_common_table(label, counter, n=10, style_fn=code, header_level=3, use_blockquote=False):
    if n > len(counter):
        n = len(counter)

    tabel_label = f"Top {n} {label.title() if not label.isupper() else label}" \
        + ('s' if not label.endswith('s') else '')
    table_md = f"Total {label}s: {code(sum(counter.values()))}\nUnique: {code(len(counter))}\n"

    headers = [label, "Times Seen"]
    if isinstance(label, (tuple, list)):
        headers = label[:2]

    table_md += table(headers, [(item, count)
                      for item, count in counter.most_common(n)], style_fn)
    md = collapseable_section(table_md, tabel_label,
                              header_level, use_blockquote)

    return md
