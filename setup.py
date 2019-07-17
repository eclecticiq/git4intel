import importlib.machinery

loader = importlib.machinery.SourceFileLoader('indices', './setup/indices.py')
indices = loader.load_module('indices')

loader = importlib.machinery.SourceFileLoader('attack', './data/attack.py')
attack = loader.load_module('attack')

indices.main()
attack.main()
