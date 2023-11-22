from selenium.webdriver.chrome.service import Service as ChromeService
from selenium.webdriver.chrome.options import Options as ChromeOptions  # noqa
from selenium.webdriver.chrome.webdriver import WebDriver as Chrome  # noqa

from selenium.webdriver.edge.service import Service as EdgeService
from selenium.webdriver.edge.options import Options as EdgeOptions  # noqa
from selenium.webdriver.edge.webdriver import WebDriver as Edge  # noqa

from selenium.webdriver.firefox.service import Service as FirefoxService
from selenium.webdriver.firefox.options import Options as FirefoxOptions  # noqa
from selenium.webdriver.firefox.webdriver import WebDriver as Firefox  # noqa

from selenium.webdriver.ie.service import Service as IeService
from selenium.webdriver.ie.options import Options as IeOptions  # noqa
from selenium.webdriver.ie.webdriver import WebDriver as Ie  # noqa

from selenium.webdriver.safari.service import Service as SafariService
from selenium.webdriver.safari.webdriver import WebDriver as Safari  # noqa

from selenium.webdriver.webkitgtk.service import Service as WebKitGTKService
from selenium.webdriver.webkitgtk.options import Options as WebKitGTKOptions  # noqa
from selenium.webdriver.webkitgtk.webdriver import WebDriver as WebKitGTK  # noqa


from selenium.webdriver.wpewebkit.service import Service as WPEWebKitService
from selenium.webdriver.wpewebkit.options import Options as WPEWebKitOptions  # noqa
from selenium.webdriver.wpewebkit.webdriver import WebDriver as WPEWebKit 


from selenium.webdriver.common.by import By
from selenium.webdriver.common.keys import Keys
from selenium.common.exceptions import NoSuchElementException, StaleElementReferenceException

from selenium.webdriver.support.wait import WebDriverWait
from selenium.webdriver.support import expected_conditions as EC


from bs4 import BeautifulSoup
from time import sleep


SELENIUM_WEBDRIVER_CLASSES = {
    "chrome": (Chrome, ChromeService, ChromeOptions),
    "edge": (Edge, EdgeService, EdgeOptions),
    "firefox": (Firefox, FirefoxService, FirefoxOptions),
    "ie": (Ie, IeService, IeOptions),
    "safari": (Safari, SafariService, None),
    "webkitgtk": (WebKitGTK, WebKitGTKService, WebKitGTKOptions),
    "wpewebkit": (WPEWebKit, WPEWebKitService, WPEWebKitOptions)
}

class SoupScraper(object):
    def __init__(self, selenium_webdriver_type="chrome", selenium_service_kwargs={}, selenium_options_kwargs={}, keep_alive=True) -> None:
        selenium_webdriver_cls, selenium_service_cls, selenium_options_cls = SELENIUM_WEBDRIVER_CLASSES[selenium_webdriver_type] 
        
        self.selenium_service = selenium_service_cls(**selenium_service_kwargs)
        self.selenium_options = selenium_options_cls(**selenium_options_kwargs)
        self.webdriver = selenium_webdriver_cls(service=self.selenium_service, options=self.selenium_options, keep_alive=keep_alive)


    def get_soup(self):
        return BeautifulSoup(self.webdriver.page_source, 'html.parser')
    
    
    @property
    def soup(self):
        return self.get_soup()

    def get_current_url(self):
        return self.webdriver.current_url
    
    @property
    def current_url(self):
        return self.get_current_url()
    
    def goto(self, url):
        self.webdriver.get(url)

    def gotos(self, url, sleep_secs=5.0):
        """Goto url and sleep for sleep_secs"""
        self.webdriver.get(url)
        if sleep_secs and sleep_secs > 0:
            sleep(sleep_secs)

    def back(self):
        self.webdriver.back()

    def quit(self):
        self.webdriver.quit()
    
    def wait_until_find_element(self, locator, locator_value, timeout=10.0, poll_frequency=0.5,ignored_exceptions=None):
        wait = WebDriverWait(self.webdriver, timeout, poll_frequency, ignored_exceptions)
        element = wait.until(lambda x: x.find_element(locator, locator_value))
        #element = WebDriverWait(self.webdriver, timeout, poll_frequency, ignored_exceptions).until(lambda x: x.find_element(locator, locator_value))
        return element
    
    #WAIT FOR ELEMENT METHODS -> element(s)
    def wait_for_element(self, locator, locator_value, expected_condition, timeout=3.0, poll_frequency=0.5, ignored_exceptions=None):
        try:
            wait = WebDriverWait(self.webdriver, timeout, poll_frequency, ignored_exceptions)
            element = wait.until(expected_condition((locator, locator_value)))
        except:
            element = None
        
        return element
    

    def wait_for_clickable_element(self, locator, locator_value, **wait_kwargs):
        return self.wait_for_element(locator, locator_value, EC.element_to_be_clickable, **wait_kwargs)


    def wait_for_visible_element(self, locator, locator_value, **wait_kwargs):
        return self.wait_for_element(locator, locator_value, EC.visibility_of_element_located, **wait_kwargs)
    

    #FIND ELEMENT METHODS -> element(s)
    def find_elements(self, locator, locator_value):
        return self.webdriver.find_elements(locator, locator_value)
    

    def find_element(self, locator, locator_value):
        try:
            element = self.webdriver.find_element(locator, locator_value)
        except NoSuchElementException as e:
            #print('LINE 121 ', e)
            element = None
        return element
    

    #GET ATTR/TEXT METHODS -> str,None
    def get_element_attr(self, locator, locator_value, attr):
        element = self.find_element(locator, locator_value)
        if element:
            return element.get_attribute(attr)
                 
    def get_element_text(self, locator, locator_value):
        #text = self.get_element_attr(locator, locator_value, "text")
        element = self.find_element(locator, locator_value)
        if element:
            text = element.text
        else:
            text = ''
        return text
    
    #_by_class_name SHORTCUT METHODS
    def find_elements_by_class_name(self, locator_value):
        return self.find_elements(By.CLASS_NAME, locator_value)

    def find_element_by_class_name(self, locator_value):
        return self.find_element(By.CLASS_NAME, locator_value)

    def get_text_by_class_name(self, locator_value):
        return self.get_element_text(By.CLASS_NAME, locator_value)
    
    def get_attr_by_class_name(self, locator_value, attr):
        return self.get_element_attr(By.CLASS_NAME, locator_value, attr)