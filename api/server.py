from flask import Flask, Response
import sys
import os

# Add the parent directory to sys.path
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

# Import the Flask app from index.py
from index import app

# Handler for Vercel
def handler(request):
    return app
