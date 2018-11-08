from flask import Flask, render_template, url_for, jsonify, request, redirect, session, flash
from flask_bootstrap import Bootstrap
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import logging, os, json, random, re, string, datetime, bcrypt, urllib, hashlib
from logging.handlers import RotatingFileHandler
from forms import SignupForm, LoginForm
from functools import wraps
from flask_mail import Mail

app = Flask(__name__)
bootstrap = Bootstrap(app)

# Load configuration file
app.config.from_pyfile("config/defaults.py")
app.secret_key = app.config['SECRET_KEY']
# Connect to the mail server
mail = Mail(app)

# Connect to the DB and load tables	
mongo = PyMongo(app)
print "MongoDB connected successfully"
users = mongo.db.users
lifts = mongo.db.lifts
profiles = mongo.db.profiles

from compoundlifts import routes