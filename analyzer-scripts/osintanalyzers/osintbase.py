from analyzerbase import *
from .soupscraper import *
from copy import deepcopy

import requests
# from time import sleep

class RateLimitError(Exception):
    pass


class OSINTAnalyzerBase:
    SOURCES = []#["isc", "whois", "cybergordon", "threatfox", "shodan"]

    def __init__(self, 
                 db_path=Path("tests/osintdb"), 
                 selenium_webdriver_type="chrome", 
                 webdriver_path="/Users/lucasfaudman/Documents/SANS/internship/chromedriver",
                 max_errors={
                 }):
        
        self.db_path = db_path

        if not self.db_path.exists():
            self.db_path.mkdir(parents=True)

        self.selenium_webdriver_type = selenium_webdriver_type
        self.webdriver_path = webdriver_path
        self._scraper = None

        self.max_errors = max_errors

        # So it can be added as Attack postprocessor
        self.attacks = {}
        

    @property
    def scraper(self):

        #Don't create scraper until needed
        if not self._scraper:
            self._scraper = SoupScraper(
                selenium_webdriver_type=self.selenium_webdriver_type, 
                selenium_service_kwargs={"executable_path":self.webdriver_path}, 
                selenium_options_kwargs={}, 
                keep_alive=True)
        
        return self._scraper


    def __del__(self):
        if self._scraper:
            self._scraper.quit()


    def get_empty_ouput(self, sharing_link="", default_results={}, default_error=""):
        return {"sharing_link": sharing_link, 
                "results": default_results, 
                "error": default_error}


    def read_data_for_source(self, arg, source):

        arg_source_file = self.db_path / f"{source}/{arg.replace('/','_')}.json"
        if arg_source_file.exists():
    
            with arg_source_file.open() as f:
                return json.loads(f.read())



    def write_data_for_source(self, arg, source, data):

        arg_source_file = self.db_path / f"{source}/{arg.replace('/','_')}.json"
        if not arg_source_file.parent.exists():
            arg_source_file.parent.mkdir(parents=True)
        
        with arg_source_file.open("w+") as f:
            json.dump(data, f, indent=2)


    def get_data(self, args, arg_type="ip", sources=[], update_counts=True):
        sources = sources or self.SOURCES
        data = {}
        error_counts = Counter()

        if update_counts:
            data['counts'] = defaultdict(lambda: defaultdict(Counter))

        for arg in args:
            data[str(arg)] = {}
            
            for source in sources:
                
                
                saved_source_data = self.read_data_for_source(arg, source)
                if saved_source_data:
                    print(f"Using saved {source} data {arg_type} for {arg}")
                    source_data = saved_source_data                
                
                elif error_counts[source] >= self.max_errors[source]:    
                    print(f"Max errors reached for {source} skipping {arg}")
                    continue

                else:
                    try:
                        print(f"Getting data for {arg} from {source}")
                        source_data = getattr(self, f"check_{source}")(arg, arg_type)
                        self.write_data_for_source(arg, source, source_data)

    
                    except Exception as e:
                        err_msg = f"ERROR: Error caught while getting data for {arg} from {source}: {e}"
                        print(err_msg)

                        error_counts[source] += 1
                        source_data = self.get_empty_ouput("", {}, err_msg)
                    
                    
                

                data[arg][source] = source_data
                if update_counts:
                    data = getattr(self, f"count_{source}")(data, arg)
                

        return data
    



    def get_reduced_data(self, args, arg_type="ip", sources=SOURCES,  update_counts=False, keep_errors=False):
        data = self.get_data(args, arg_type, sources, update_counts)
        reduced = data
        #reduced = deepcopy(data)


        for arg in args:
            for source in sources:

                if data[arg][source].get("results"):
                    # Only leave results and reduce nesting by one level
                    reduced[arg][source] = data[arg][source]["results"]
                    # Reduce results for each source
                    reduced[arg][source] = getattr(self, f"reduce_{source}")(reduced[arg][source])

                else:                 
                    #Only leave error message
                    reduced[arg][source] = data[arg][source].get('error') if keep_errors else ""



        return reduced


    

    # def update_counts(self, data, arg, sources=SOURCES):
    #     sources = sources or self.SOURCES
    #     if not data.get('counts'):
    #         data['counts'] = defaultdict(lambda: defaultdict(Counter))
        
    #     for source in sources:
    #         data = getattr(self, f"count_{source}")(data, arg)
        
    #     return data