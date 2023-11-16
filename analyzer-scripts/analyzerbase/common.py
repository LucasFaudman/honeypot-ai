import re
import hashlib 
from collections import defaultdict, OrderedDict, Counter
import os
import pathlib
import json
from datetime import datetime
from pprint import pprint
import tldextract

MYIPS = os.environ.get("MYIPS", "").split(",")
test_logs_path = pathlib.Path("/Users/lucasfaudman/Documents/SANS/internship/tests/logs")
test_attacks_path = pathlib.Path("/Users/lucasfaudman/Documents/SANS/internship/tests/attacks")