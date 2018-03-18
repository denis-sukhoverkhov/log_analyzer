# Log Analyzer

### Prerequisites for development environment installation

1. [Python 3.6](https://www.python.org/downloads/release/python-360/)


### Start unittests

```bash
python3.6 -m unittest
``` 

### Start the analyzer

1. Create config-file from sample ``config.sample.json``
```bash
cp config.sample.json config.json
```

2. Specify the path to the directory with logs in the config, by default the path is ``./log``. 
The default logging is written to the file ``/var/tmp/log_nalyzer.ts``

3. Run the analyzer

```bash
python3.6 log_analyzer.py
```