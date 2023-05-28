#!/usr/bin/python3
import sys
sys.path.insert(0,"/var/www/edm/venv/lib/python3.9/site-packages")
sys.path.insert(0, "/var/www/edm/")

from app import create_app
application = create_app()
