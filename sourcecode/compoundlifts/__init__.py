from flask import Flask, render_template, url_for, jsonify, request, redirect, session, flash
from flask_bootstrap import Bootstrap
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import logging, os, json, random, re, string, datetime, bcrypt, urllib, hashlib
from logging.handlers import RotatingFileHandler
from forms import SignupForm, LoginForm
from functools import wraps
from flask_mail import Mail
#from itsdangerous import TimedJSONWebSignatureSerializer as Serializer

app = Flask(__name__)
bootstrap = Bootstrap(app)

app.config.from_pyfile("config/defaults.py")

app.secret_key = app.config['SECRET_KEY']
mail = Mail(app)

# Read DB collection	
mongo = PyMongo(app)
print "MongoDB connected successfully"
users = mongo.db.users

from compoundlifts import routes