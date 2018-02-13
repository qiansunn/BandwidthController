#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import sys

from ryu.cmd import manager

def main():
    sys.argv.append('app/route_module.py')
    sys.argv.append('app/topo_module.py')
    sys.argv.append('--verbose')
    sys.argv.append('--enable-debugger')
    sys.argv.append('--observe-links')
    sys.exit(manager.main())

if __name__ == '__main__':
    main()
