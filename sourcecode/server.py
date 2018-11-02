from flask import Flask, render_template, url_for, jsonify, request, redirect, session, flash
from flask_bootstrap import Bootstrap
from flask_pymongo import PyMongo
import ConfigParser, logging, os, json, random, re, string, datetime, bcrypt
from logging.handlers import RotatingFileHandler
from flask_wtf import FlaskForm
from wtforms import StringField, TextAreaField, PasswordField, validators
app = Flask(__name__)
bootstrap = Bootstrap(app)

@app.route('/')
def index():
	#form = SignupForm()
	#if 'email' in session:
	#	return render_template('index.html', email=session['email'])
	return render_template('index.html')

@app.context_processor
def inject_form():
	form = SignupForm()
	return dict(form=form) 

@app.errorhandler(404)
def error_400(e):
	return render_template('error.html', error=404), 404


@app.errorhandler(500)
def error_500(e):
	return render_template('error.html', error=500), 500

@app.route('/login/', methods=['POST', 'GET'])
def login():
	form = LoginForm(request.form)
	if request.method =='POST':
		# Validate Login Request
		print ""
	return render_template('login.html', form=form)

class LoginForm(FlaskForm):
	email = StringField('email', [validators.Email()])
	password = PasswordField('password', [
		validators.Length(min=8, max=50)
	])


class SignupForm(FlaskForm):
	firstname = StringField('firstname', [validators.Length(min=2, max=50)])
	lastname = StringField('lastname', [validators.Length(min=2, max=50)])
	email = StringField('email', [validators.Email()])
	password = PasswordField('password', [
		validators.Length(min=8, max=50),
		validators.EqualTo('confirm', message='Passwords do not match')
	])
	confirm = PasswordField('confirm')


@app.route('/signup/', methods=['POST', 'GET'])
def signup():
	form = SignupForm(request.form)

	if request.method == 'POST' and form.validate():
		current_datetime = datetime.datetime.now()

		first_name = form.firstname.data
		last_name = form.lastname.data
		email = form.email.data.lower()
		created = current_datetime
		last_updated = current_datetime
		is_admin = False
		followers = []
		following = []

		users = mongo.db.users

		existing_user = users.find_one({'email' : request.form['email']})

		if existing_user is None:
			hashpass = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
			users.insert({
				'first_name' : first_name,
				'last_name' : last_name,
				'email' : email,
				'password' : hashpass,
				'created' : created,
				'last_updated' : last_updated,
				'is_admin' : is_admin,
				'followers' : followers,
				'following' : following
				})
			session['email'] = request.form['email'].lower()
			flash('You are now registered and can log in', 'success')
        	return redirect(url_for('login'))
	return render_template('signup.html', form=form)

def init(app):
	config = ConfigParser.ConfigParser()
	try:
		config_location = "etc/defaults.cfg"
		config.read(config_location)

		app.config['DEBUG'] = config.get("config", "DEBUG")
		app.config['ip_address'] = config.get("config", "IP_ADDRESS")
		app.config['port'] = config.get("config", "PORT")
		app.config['url'] = config.get("config", "URL")

		app.config['log_location'] = config.get("logging", "LOCATION")
		app.config['log_file'] = config.get("logging", "NAME")
		app.config['log_level'] = config.get("logging", "LEVEL")
		
		app.config['MONGO_DBNAME'] = "compound-lifts"
		app.config["MONGO_URI"] = "mongodb://server:connector00@ds111192.mlab.com:11192/compound-lifts"
	except:
		print ("Could not read configs from: ", config_location)


def logs(app):
	log_pathname = app.config['log_location'] + app.config['log_file']
	file_handler = RotatingFileHandler(
		log_pathname, maxBytes=(1024 * 1024 * 10), backupCount=1024)
	file_handler.setLevel(app.config['log_level'])
	formatter = logging.Formatter(
		"%(levelname)s | %(module)s | %(funcName)s | %(message)s")
	file_handler.setFormatter(formatter)
	app.logger.setLevel(app.config['log_level'])
	app.logger.addHandler(file_handler)


if __name__ == '__main__':
	init(app)
	logs(app)
	mongo = PyMongo(app)
	print "MongoDB connected successfully"
	app.secret_key = 'lift-compound-'
	app.run(
		host=app.config['ip_address'],
		port=int(app.config['port']))
else:
	init(app)
	logs(app)
	mongo = PyMongo(app)
	print "MongoDB connected successfully"
	random = os.urandom(24)
	app.secret_key = random
