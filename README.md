# tcp-traffic-analyzer

## Instructions to Run

### Method A: Default .cap file
To use the sample .cap file provided in the folder, follow these steps:

1. Ensure you are in the directory containing `TrafficAnalyzer.py` and `sample-capture-file.cap`.
2. In the terminal run the command `python3 TrafficAnalyzer.py`.

### Method B: Custom .cap file
To use a different cap file than the one provided in the terminal, follow these steps:

1. Place the capture file into the same directory containing `TrafficAnalyzer.py` (optional).
2. Ensure you are in the directory containing `TrafficAnalyzer.py`.
3. (If custom capture file is in same directory) Run `python3 TrafficAnalyzer.py <capfile>`
4. (If custom capture file is elsewhere) Run `python3 TrafficAnalyzer.py /path/to/file/<name>.cap`
