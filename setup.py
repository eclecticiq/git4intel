import importlib.machinery

loader = importlib.machinery.SourceFileLoader('indices', './setup/indices.py')
indices = loader.load_module('indices')

loader = importlib.machinery.SourceFileLoader('attack', './data/attack.py')
attack = loader.load_module('attack')

from indices import *
from attack import *


def main():
    indices.main()
    attack.main()


if __name__ == "__main__":
    main()
