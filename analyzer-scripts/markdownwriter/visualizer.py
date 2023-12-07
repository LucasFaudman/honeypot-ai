import matplotlib.pyplot as plt
from collections import Counter
from pathlib import Path


class CounterGrapher:

    def __init__(self, outpath: Path, counter: Counter, n=10, title="", xlabel="", ylabel=""):
        self.outpath = outpath
        self.counter = counter
        self.title = title
        self.xlabel = xlabel
        self.ylabel = ylabel

        if self.counter:
            self.labels, self.values = zip(*self.counter.most_common(n))
            self.labels = [str(label) for label in self.labels]
            self.total = sum(self.values)
            self.percentages = [value / self.total for value in self.values]
        else:
            self.labels, self.values = (), ()
            self.total = 0
            self.percentages = ()

    
    def bar(self):
        plt.clf()
        plt.bar(self.labels, self.values)
        plt.xlabel(self.xlabel)
        plt.ylabel(self.ylabel)

        plt.title(self.title)
        # plt.tight_layout()

        plt.savefig(self.outpath)
        plt.close()

    def pie(self):
        plt.clf()
        plt.pie(self.values, labels=self.labels, autopct='%1.1f%%', shadow=True, startangle=90)
        
        plt.title(self.title)
        # plt.tight_layout()

        plt.savefig(self.outpath)
        plt.close()

    def hist(self):
        plt.clf()
        plt.hist(self.values, bins=len(self.counter), align='left')
        plt.xlabel('Values')
        plt.ylabel('Frequency')
        
        plt.title(self.title)
        
        # plt.tight_layout()
        plt.savefig(self.outpath)
        plt.close()

    def plot(self):
        print(self.bar())
        print(self.pie())
        print(self.hist())
    



if __name__ == "__main__":
    pass