import re
import hashlib 
from collections import defaultdict, OrderedDict, Counter
import os
from pathlib import Path
import json
from datetime import datetime
from typing import Union
from urllib.parse import urlparse
from unittest import TestCase
from pprint import pprint
from time import sleep
from ordered_set import OrderedSet

MYIPS = os.environ.get("MYIPS", "").split(",")
test_logs_path = Path("/Users/lucasfaudman/Documents/SANS/internship/tests/logs")
test_attacks_path = Path("/Users/lucasfaudman/Documents/SANS/internship/tests/attacks/")


class SetReprOrderedSet(OrderedSet):
    """OrderedSet that prints as a normal python set instead of a list when using repr()"""
    def __repr__(self):
        return "{" + f"{list(self)}"[1:-1] + "}"
    

    def __add__(self, other):
        self = self.union(other)
        return self