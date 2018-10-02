# angr side channel analysis script
Improving side channel analysis techniques for CTF problems.

Side channel analysis for CTF problems can be pretty incosistent. [PinCTF](https://github.com/ChrisTheCoolHut/PinCTF) used against the "Crack" binary provided will provide different results for every run. By lifting these instructions to an IR without any pesky branch predictor getting in our way, we can get consistent instruction count using [angr](https://github.com/angr). 

[![asciicast](https://asciinema.org/a/QYdKtutCYfLEQmD0vvw29hUcA.png)](https://asciinema.org/a/QYdKtutCYfLEQmD0vvw29hUcA)

```
$ python angr_side_channel.py -h
usage: angr_side_channel.py [-h] (--stdin | --arg) [-i INPUTLENGTH] [-r]
                            [-c PROCCOUNT]
                            File

positional arguments:
  File                  File to analyze

optional arguments:
  -h, --help            show this help message and exit
  --stdin               Send inputs through STDIN
  --arg                 Send inputs through argv[2]
  -i INPUTLENGTH, --inputLength INPUTLENGTH
                        Length of input
  -r, --reverse         Reverse input checking
  -c PROCCOUNT, --procCount PROCCOUNT
                        Multiprocess count

```
An example command is below
```
python angr_side_channel.py challenges/ELF-NoSoftwareBreakpoints -i 25 --stdin -r -c 4
```
