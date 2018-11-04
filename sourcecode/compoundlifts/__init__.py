from flask import Flask, render_template, url_for, jsonify, request, redirect, session, flash
from flask_bootstrap import Bootstrap
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import ConfigParser, logging, os, json, random, re, string, datetime, bcrypt, urllib, hashlib
from logging.handlers import RotatingFileHandler
from forms import SignupForm, LoginForm
from functools import wraps

app = Flask(__name__)
bootstrap = Bootstrap(app)
app.secret_key = os.urandom(24)

# Setup DB config
app.config['MONGO_DBNAME'] = "compound-lifts"
app.config["MONGO_URI"] = "mongodb://server:connector00@ds111192.mlab.com:11192/compound-lifts"

# Read DB collection	
mongo = PyMongo(app)
print "MongoDB connected successfully"
users = mongo.db.users


def setup_config(app):
    config = ConfigParser.ConfigParser()
    try:
        config_location = "config/defaults.cfg"
        config.read(config_location)

        app.config['DEBUG'] = config.get("config", "DEBUG")
        app.config['ip_address'] = config.get("config", "IP_ADDRESS")
        app.config['port'] = config.get("config", "PORT")
        app.config['url'] = config.get("config", "URL")

    except:
        print ("Could not read configs from: ", config_location)

setup_config(app)

from compoundlifts import routes