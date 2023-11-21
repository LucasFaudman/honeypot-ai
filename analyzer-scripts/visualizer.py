from typing import Any
import matplotlib.pyplot as plt
from collections import Counter
from pathlib import Path


class CounterGrapher:

    def __init__(self, outpath: Path, counter: Counter, title="", xlabel="", ylabel=""):
        self.outpath = outpath
        self.counter = counter
        self.title = title
        self.xlabel = xlabel
        self.ylabel = ylabel

        self.labels, self.values = zip(*self.counter.items())
        self.labels = [str(label) for label in self.labels]
        self.total = sum(self.values)
        self.percentages = [value / self.total for value in self.values]
        
    
    def bar(self):
        plt.clf()
        plt.bar(self.labels, self.values)
        plt.xlabel(self.xlabel)
        plt.ylabel(self.ylabel)

        plt.title(self.title)
        plt.tight_layout()

        plt.savefig(self.outpath) # / "bar.png")
        plt.close()

    def pie(self):
        plt.clf()
        plt.pie(self.values, labels=self.labels, autopct='%1.1f%%', shadow=True, startangle=90)
        
        plt.title(self.title)
        plt.tight_layout()

        plt.savefig(self.outpath) # / "pie.png")
        plt.close()

    def hist(self):
        plt.clf()
        plt.hist(self.values, bins=len(self.counter), align='left')
        plt.xlabel('Values')
        plt.ylabel('Frequency')
        
        plt.title(self.title)
        
        plt.tight_layout()
        plt.savefig(self.outpath) # / "hist.png")
        plt.close()

    def plot(self):
        print(self.bar())
        print(self.pie())
        print(self.hist())
    

def test_counter_grapher():
    counter = Counter(['A', 'B', 'A', 'C', 'B', 'A', 'D', 'C', 'A', 'B', 'E'])
    grapher = CounterGrapher("/Users/lucasfaudman/Documents/SANS/internship/tests/observations", counter)
    grapher.plot()

if __name__ == "__main__":
    test_counter_grapher()