from analyzerbase import *
from .soupscraper import *
import requests


class RateLimitError(Exception):
    pass


class OSINTAnalyzerBase:
    """Base class for OSINT analyzers that get data from OSINT sources and save it to a database"""

    SOURCES = []

    def __init__(self, 
                 db_path=Path("tests/osintdb"), 
                 selenium_webdriver_type="chrome", 
                 webdriver_path="/Users/lucasfaudman/Documents/SANS/internship/chromedriver",
                 sources=[],
                 max_errors: Union[int, dict]={}
                 ):
        
        # Create db_path if it doesn't exist for saving data
        self.db_path = db_path
        if not self.db_path.exists():
            self.db_path.mkdir(parents=True)

        # Store selenium_webdriver_type and webdriver_path for SoupScraper to use when needed
        self.selenium_webdriver_type = selenium_webdriver_type
        self.webdriver_path = webdriver_path
        self._scraper = None

        # Store sources to get data from
        self.SOURCES = sources or self.SOURCES

        # Store max_errors for each source. If max_errors is an int, use it for all sources
        if isinstance(max_errors, int):
            self.max_errors = {source: max_errors for source in self.SOURCES}
        else:
            self.max_errors = max_errors

            
    @property
    def scraper(self):
        """SoupScraper object for scraping web pages"""
        #Don't create scraper until needed
        if not self._scraper:
            self._scraper = SoupScraper(
                selenium_webdriver_type=self.selenium_webdriver_type, 
                selenium_service_kwargs={"executable_path":self.webdriver_path}, 
                selenium_options_kwargs={}, 
                keep_alive=True)
        
        return self._scraper


    def __del__(self):
        """Quit scraper if it exists when object is deleted or garbage collected"""
        if self._scraper:
            self._scraper.quit()


    def get_output_template(self, sharing_link="", default_results={}, default_error=""):
        """Returns empty output template with sharing_link, results, and error"""
        return {"sharing_link": sharing_link, 
                "results": default_results, 
                "error": default_error}


    def read_data_for_source(self, arg, source):
        """Reads data for arg from source if it exists or returns None"""
        # Replace / in arg with _ to avoid creating subdirectories
        arg_source_file = self.db_path / f"{source}/{arg.replace('/','_')}.json"
        if arg_source_file.exists():
            with arg_source_file.open() as f:
                return json.loads(f.read())
        


    def write_data_for_source(self, arg, source, data):
        """Writes data for arg from source to file"""

        # Replace / in arg with _ to avoid creating subdirectories
        arg_source_file = self.db_path / f"{source}/{arg.replace('/','_')}.json"
        if not arg_source_file.parent.exists():
            arg_source_file.parent.mkdir(parents=True)
        
        with arg_source_file.open("w+") as f:
            json.dump(data, f, indent=2)


    def get_data(self, args, arg_type="ip", sources=[], update_counts=True):
        """
        Gets full data for args from sources and returns it in a dict with args as keys and sources as subkeys
        args: list of args to get data for
        arg_type: type of args (ip, domain, etc.) used to tell check{source} methods how to get data
        sources: list of sources to get data from
        update_counts: whether to update data['counts'] for each source
        """

        sources = sources or self.SOURCES
        data = {}
        error_counts = Counter()

        if update_counts:
            # Create data['counts'] nested defaultdict of Counters
            data['counts'] = defaultdict(lambda: defaultdict(Counter))

        for arg in args:
            # Make sure arg is a hashable by converting to string
            if not isinstance(arg, str):
                arg = str(arg)
            
            # Create empty dict for arg in data
            data[arg] = {}
            
            for source in sources:
                
                # Use saved data if it exists
                saved_source_data = self.read_data_for_source(arg, source)
                if saved_source_data:
                    print(f"Using saved {source} data {arg_type} for {arg}")
                    source_data = saved_source_data                
                
                # Skip if max errors reached
                elif error_counts[source] >= self.max_errors[source]:    
                    print(f"Max errors reached for {source} skipping {arg}")
                    continue

                else:
                    # Otherwise try to get data from source using check_{source} method
                    try:
                        print(f"Getting data for {arg} from {source}")
                        source_data = getattr(self, f"check_{source}")(arg, arg_type)
                        
                        # Write data to file if no errors occured when getting data
                        self.write_data_for_source(arg, source, source_data)

    
                    except Exception as e:
                        err_msg = f"ERROR: Error caught while getting data for {arg} from {source}: {e}"
                        print(err_msg)

                        # Set source data to empty output with only error message
                        error_counts[source] += 1
                        source_data = self.get_output_template("", {}, err_msg)
                    
                    
                # Add source data for arg to data (output)
                data[arg][source] = source_data
                
                # Update data['counts'] with count_{source} method if update_counts is True
                if update_counts:
                    data = getattr(self, f"count_{source}")(data, arg)
                

        return data
    



    def get_reduced_data(self, args, arg_type="ip", sources=SOURCES,  update_counts=False, keep_errors=False):
        """
        Gets reduced data for args from sources and returns it in a dict with args as keys and sources as subkeys
        Used to minimize number of tokens when passing data to OpenAI API.
        Same iterface as get_data method but calls the reduce_{source} method for each source to reduce the data.
        """
        
        data = self.get_data(args, arg_type, sources, update_counts)
        reduced = data
        
        for arg in args:
            for source in sources:

                if data[arg][source].get("results"):
                    # Only leave results and reduce nesting by one level
                    reduced[arg][source] = data[arg][source]["results"]
                    # Reduce results for each source
                    reduced[arg][source] = getattr(self, f"reduce_{source}")(reduced[arg][source])

                else:                 
                    #Only leave error message if keep_errors is True otherwise leave empty string
                    reduced[arg][source] = data[arg][source].get('error') if keep_errors else ""


        return reduced


