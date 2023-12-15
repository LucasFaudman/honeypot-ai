
from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException

from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


from bs4 import BeautifulSoup
from time import sleep

def import_webdriver(webdriver_type):
    """Conditionally Imports and returns Selenium WebDriver class, Service class, and Options class for webdriver_type"""

    webdriver_modules = {
        'chrome': {
            'Service': 'selenium.webdriver.chrome.service',
            'Options': 'selenium.webdriver.chrome.options',
            'WebDriver': 'selenium.webdriver.chrome.webdriver'
        },
        'edge': {
            'Service': 'selenium.webdriver.edge.service',
            'Options': 'selenium.webdriver.edge.options',
            'WebDriver': 'selenium.webdriver.edge.webdriver'
        },
        'firefox': {
            'Service': 'selenium.webdriver.firefox.service',
            'Options': 'selenium.webdriver.firefox.options',
            'WebDriver': 'selenium.webdriver.firefox.webdriver'
        },
        'ie': {
            'Service': 'selenium.webdriver.ie.service',
            'Options': 'selenium.webdriver.ie.options',
            'WebDriver': 'selenium.webdriver.ie.webdriver'
        },
        'safari': {
            'Service': 'selenium.webdriver.safari.service',
            'WebDriver': 'selenium.webdriver.safari.webdriver'
        },
        'webkitgtk': {
            'Service': 'selenium.webdriver.webkitgtk.service',
            'Options': 'selenium.webdriver.webkitgtk.options',
            'WebDriver': 'selenium.webdriver.webkitgtk.webdriver'
        },
        'wpewebkit': {
            'Service': 'selenium.webdriver.wpewebkit.service',
            'Options': 'selenium.webdriver.wpewebkit.options',
            'WebDriver': 'selenium.webdriver.wpewebkit.webdriver'
        },
        # Add more webdrivers as needed
    }

    if webdriver_type in webdriver_modules:
        module = webdriver_modules[webdriver_type]
        from importlib import import_module
        return (
            import_module(module['WebDriver']).WebDriver,
            import_module(module['Service']).Service,
            import_module(module['Options']).Options if 'Options' in module else None
        )
    else:
        raise ValueError(f"Unsupported webdriver type: {webdriver_type}")



class SoupScraper(object):
    def __init__(self, 
                 selenium_webdriver_type="chrome", 
                 selenium_service_kwargs={}, 
                 selenium_options_kwargs={}, 
                 keep_alive=True
                 ) -> None:
        
        # Import Selenium WebDriver class, Service class, and Options class for webdriver_type
        selenium_webdriver_cls, selenium_service_cls, selenium_options_cls = import_webdriver(selenium_webdriver_type)

        # Create Selenium Service and Options objects
        self.selenium_service = selenium_service_cls(**selenium_service_kwargs)
        self.selenium_options = selenium_options_cls(**selenium_options_kwargs) if selenium_options_cls else None
        # Create Selenium WebDriver object from Service and Options objects
        self.webdriver = selenium_webdriver_cls(service=self.selenium_service, options=self.selenium_options, keep_alive=keep_alive)

    def __del__(self):
        """Quit webdriver when SoupScraper object is deleted or garbage collected"""
        self.webdriver.quit()


    def get_soup(self):
        """Returns BeautifulSoup object from webdriver.page_source"""
        return BeautifulSoup(self.webdriver.page_source, 'html.parser')
    
    
    @property
    def soup(self):
        """Returns BeautifulSoup object from webdriver.page_source"""
        return self.get_soup()

    def get_current_url(self):
        """Returns webdriver.current_url"""
        return self.webdriver.current_url
    
    @property
    def current_url(self):
        """Returns webdriver.current_url"""
        return self.get_current_url()
    
    def goto(self, url):
        """Goto url with webdriver.get(url)"""
        self.webdriver.get(url)

    def gotos(self, url, sleep_secs=5.0):
        """Goto url with webdriver.get(url) and sleep for sleep_secs"""
        self.webdriver.get(url)
        if sleep_secs and sleep_secs > 0:
            sleep(sleep_secs)

    def back(self):
        """Goto previous page with webdriver.back()"""
        self.webdriver.back()

    def quit(self):
        """Quit webdriver with webdriver.quit()"""
        self.webdriver.quit()
    
    def wait_until_find_element(self, locator, locator_value, timeout=10.0, poll_frequency=0.5,ignored_exceptions=None):
        """Wait until element is found with webdriver.find_element(locator, locator_value)"""
        wait = WebDriverWait(self.webdriver, timeout, poll_frequency, ignored_exceptions)
        element = wait.until(lambda x: x.find_element(locator, locator_value))
        #element = WebDriverWait(self.webdriver, timeout, poll_frequency, ignored_exceptions).until(lambda x: x.find_element(locator, locator_value))
        return element
    
    #WAIT FOR ELEMENT METHODS -> element(s)
    def wait_for_element(self, locator, locator_value, expected_condition, timeout=3.0, poll_frequency=0.5, ignored_exceptions=None):
        """Wait for element with expected_condition(locator, locator_value) or return None if timeout"""
        try:
            wait = WebDriverWait(self.webdriver, timeout, poll_frequency, ignored_exceptions)
            element = wait.until(expected_condition((locator, locator_value)))
        except:
            element = None
        
        return element
    

    def wait_for_clickable_element(self, locator, locator_value, **wait_kwargs):
        """Wait for clickable element with EC.element_to_be_clickable(locator, locator_value)"""
        return self.wait_for_element(locator, locator_value, EC.element_to_be_clickable, **wait_kwargs)


    def wait_for_visible_element(self, locator, locator_value, **wait_kwargs):
        """Wait for visible element with EC.visibility_of_element_located(locator, locator_value)"""
        return self.wait_for_element(locator, locator_value, EC.visibility_of_element_located, **wait_kwargs)
    

    #FIND ELEMENT METHODS -> element(s)
    def find_elements(self, locator, locator_value):
        """Find multiple elements with webdriver.find_elements(locator, locator_value)"""
        return self.webdriver.find_elements(locator, locator_value)
    

    def find_element(self, locator, locator_value):
        """Find element with webdriver.find_element(locator, locator_value) or return None if NoSuchElementException"""
        try:
            element = self.webdriver.find_element(locator, locator_value)
        except NoSuchElementException as e:
            element = None
        return element
    

    #GET ATTR/TEXT METHODS -> str,None
    def get_element_attr(self, locator, locator_value, attr):
        """Finds element with webdriver.find_element(locator, locator_value) and returns element.get_attribute(attr) or None if NoSuchElementException"""
        element = self.find_element(locator, locator_value)
        if element:
            return element.get_attribute(attr)
                 
    def get_element_text(self, locator, locator_value):
        """Finds element with webdriver.find_element(locator, locator_value) and returns element.text or '' if NoSuchElementException"""
        element = self.find_element(locator, locator_value)
        if element:
            text = element.text
        else:
            text = ''
        return text
    
    #_by_class_name SHORTCUT METHODS
    def find_elements_by_class_name(self, locator_value):
        """Shortcut for find_elements(By.CLASS_NAME, locator_value)"""
        return self.find_elements(By.CLASS_NAME, locator_value)

    def find_element_by_class_name(self, locator_value):
        """Shortcut for find_element(By.CLASS_NAME, locator_value)"""
        return self.find_element(By.CLASS_NAME, locator_value)

    def get_text_by_class_name(self, locator_value):
        """Shortcut for get_element_text(By.CLASS_NAME, locator_value)"""
        return self.get_element_text(By.CLASS_NAME, locator_value)
    
    def get_attr_by_class_name(self, locator_value, attr):
        """Shortcut for get_element_attr(By.CLASS_NAME, locator_value, attr)"""
        return self.get_element_attr(By.CLASS_NAME, locator_value, attr)