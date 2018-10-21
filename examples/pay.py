from flask import Flask, request, render_template, redirect, session, abort
import urllib.parse as urlparse
import requests
import json
import random

app = Flask(__name__, template_folder='.')
app.config['SECRET_KEY'] = b'_5#y2L"F4Q8z\n\xec]/'

APP_ID  = 1
API_KEY = 'xrcyz2AaN1s9OscnpFLup5DVTi3D7WCIGhYnsmjOyCO8HjAH'
API_URL = 'https://api.easy-login.jp'    


@app.route('/')
def index():
    return redirect('/demo.html'), 301