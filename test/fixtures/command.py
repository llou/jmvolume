#! /usr/bin/env python

import sys
if len(sys.argv) > 1:
    code = int(sys.argv[1])
else:
    code = 0
text = sys.stdin.read()
sys.stdout.write(text)
sys.stderr.write(text)
sys.exit(code)
