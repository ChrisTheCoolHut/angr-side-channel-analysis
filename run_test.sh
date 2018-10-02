#!/bin/sh
python angr_side_channel.py challenges/ELF-NoSoftwareBreakpoints -i 25 --stdin -r
python angr_side_channel.py challenges/Crack -i 48 --arg
