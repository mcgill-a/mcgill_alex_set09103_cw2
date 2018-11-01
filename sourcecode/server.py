from flask import Flask, render_template, url_for, jsonify, request, redirect, session
from flask_bootstrap import Bootstrap
from flask_pymongo import PyMongo
import ConfigParser, logging, os, json, random, re, string, datetime, bcrypt
from logging.handlers import RotatingFileHandler
app = Flask(__name__)
bootstrap = Bootstrap(app)

@app.route('/')
def index():
	if 'email' in session:
		return render_template('index.html', email=session['email']) 
	return render_template('index.html')


@app.errorhandler(404)
def error_400(e):
	return render_template('error.html', error=404), 404


@app.errorhandler(500)
def error_500(e):
	return render_template('error.html', error=500), 500

@app.route('/login')
def login():
	return ""

@app.route('/signup', methods=['POST'])
def signup():
	if request.method == 'POST':
		current_datetime = datetime.datetime.now()

		first_name = request.form['first-name']
		last_name = request.form['last-name']
		email = request.form['email']
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
			session['email'] = request.form['email']
			return redirect('/')
		
		return "That email address already exists"
	return ""

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
	app.secret_key = 'lift-compound-'
	app.run(
		host=app.config['ip_address'],
		port=int(app.config['port']))
else:
	init(app)
	logs(app)
	mongo = PyMongo(app)
	app.secret_key = 'lift-compound-'
