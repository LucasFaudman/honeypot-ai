
from ipanalyzer import IPAnalyzer, json
from cowrieloganalyzer import CowrieLogAnalyzer

h1 = lambda text: '# ' + text + '\n'
h2 = lambda text: '## ' + text + '\n'
h3 = lambda text: '### ' + text + '\n'
h4 = lambda text: '#### ' + text + '\n'
italic = lambda text: '*' + text + '*'
bold = lambda text: '**' + text + '**'
link = lambda text, url: '[' + text + '](' + url + ')'
image = lambda text, url: '![' + text + '](' + url + ')'
code = lambda text: '`' + text + '`'
code_block = lambda text: '```\n' + text + '\n```\n'
blockquote = lambda text: '> ' + text + '\n'
unordered_list = lambda items: '\n'.join(['* ' + item for item in items]) + '\n'
ordered_list = lambda items: '\n'.join([f'{n}. ' + item for n,item in enumerate(items)]) + '\n'
hline = lambda: '---\n'
def table(headers, rows):
    table = ''
    table += '| ' + ' | '.join(headers) + ' |\n'
    table += '| ' + ' | '.join(['---' for _ in headers]) + ' |\n'
    for row in rows:
        row = [str(item) for item in row]
        table += '| ' + ' | '.join(row) + ' |\n'
    return table


class MarkdownWriter:
    def __init__(self, filename="test.md", md="", mode="w+"):
        self.file = open(filename, mode)
        self.md = md

    def write(self, md):
        self.file.write(md)

    def close(self):
        self.file.close()

    def update_md(self, md, data={}):
        self.md = self.prepare_md(md, data)
        self.write(self.md)

    def prepare_md(self, md, data={}):
        #Implement in subclasses
        return NotImplementedError    

class IPAnalyzerMarkdownWriter(MarkdownWriter):


    def prepare_md(self, md, data):
        md = h1("What do you know about the attacker?")
        md = self.add_ip_locations(md, data)
        md = self.add_isc(md, data)
        md = self.add_cybergordon(md, data)
        md = self.add_whois(md, data)
        #md += self.add_virustotal(md, data)

        return md

    def add_ip_locations(self, md, data):
        md += h2("IP Locations")
        location_data = [(ip, 
                        data[ip]["isc"]["ip"]["ascountry"],
                        data[ip]["isc"]["ip"]["as"],
                        data[ip]["isc"]["ip"]["asname"],
                        data[ip]["isc"]["ip"]["network"]
                        ) for ip in data]

        md += table(['IP Address', 'Country', "AS", "AS Name", "Network"], location_data)
        return md

    def add_isc(self, md, data):
        

        if len(data) == 1:
            sharing_url = list(data.values())[0]["isc"]["sharing_link"]
            sharing_link = link(sharing_url, sharing_url)
        else:
            sharing_link = link("https://isc.sans.edu/ipinfo/", "https://isc.sans.edu/ipinfo/")

        md += h2("Internet Storm Center (ISC) " + sharing_link)
        
        ics_data = [(ip, 
                        data[ip]["isc"]["ip"]["count"],
                        data[ip]["isc"]["ip"]["attacks"],
                        data[ip]["isc"]["ip"]["mindate"],
                        data[ip]["isc"]["ip"]["maxdate"],
                        data[ip]["isc"]["ip"]["updated"],
                        ) for ip in data]
        

        md += table(['IP Address', 'Total Reports', "Targets", "First Report", "Last Report", "Update Time"], ics_data)
        return md    

    def add_whois(self, md, data):
        md += h2("Whois")

        #md += table(['IP Address', 'Whois Data'], whois_data)
        for ip in data:
            md += h3(f"Whois data for: {ip}")
            md += code_block(data[ip]["whois"]["whois_raw"])

        return md

    def add_cybergordon(self, md, data):
        md += h2("CyberGordon")
        for ip in data:
            sharing_link = link(data[ip]["cybergordon"]["sharing_link"], data[ip]["cybergordon"]["sharing_link"])
            
            md += h3(f"Cybergordon results for: {ip} " + sharing_link)
            cybergordon_data = [(entry["engine"], entry["result"], entry["url"]) for entry in data[ip]["cybergordon"]["results"]["high"]]
            cybergordon_data += [(entry["engine"], entry["result"], entry["url"]) for entry in data[ip]["cybergordon"]["results"]["medium"]]
            cybergordon_data += [(entry["engine"], entry["result"], entry["url"]) for entry in data[ip]["cybergordon"]["results"]["low"]]
            md += table(['Engine', 'Results', "Url"], cybergordon_data)
        
        return md

def test_md():
    mdw = MarkdownWriter('test.md')
    mdw.write(h1('h1'))
    mdw.write(h2('h2'))
    mdw.write(h3('h3'))
    mdw.write(h4('h4'))
    mdw.write("\n"+italic('italic')+"\n")
    mdw.write("\n"+bold('bold')+"\n")
    mdw.write("\n"+link('Google.com', 'https://www.google.com')+"\n")
    mdw.write("\n"+image('image', 'https://www.google.com/images/branding/googlelogo/1x/googlelogo_color_272x92dp.png')+"\n")
    mdw.write("\n"+code('code')+"\n")
    mdw.write("\n"+code_block('code block'))
    mdw.write("\n"+blockquote('blockquote'))
    mdw.write(unordered_list(['item1', 'item2', 'item3']))
    mdw.write(ordered_list(['item1', 'item2', 'item3']))
    mdw.write(hline())
    mdw.write(table(['header1', 'header2', 'header3'], [['row1col1', 'row1col2', 'row1col3'], ['row2col1', 'row2col2', 'row2col3']]))
    mdw.close()

def test_ipanalyzer_md():
    la = CowrieLogAnalyzer()
    la.process()
    la.analyze()
    key = '6fa4c8ac58e7a1d947dc3250c39d1e27958f012e68061d8de0a7b70e3a65b906'
    src_ips = [src_ip.ip for src_ip in la.attacks[key].source_ips]
    analyzer = IPAnalyzer()
    #ip = '80.94.92.20'
    data = analyzer.get_data(src_ips)
    # data = json.load(open('testipdata.json'))
    mdw = IPAnalyzerMarkdownWriter('testip.md')
    mdw.update_md('', data)
    mdw.close()


if __name__ == "__main__":
    test_ipanalyzer_md()
