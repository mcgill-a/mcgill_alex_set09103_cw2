from flask import Flask, render_template, url_for, jsonify, request, redirect
from flask_bootstrap import Bootstrap
import ConfigParser, logging, os, json, random, re, string, time
from logging.handlers import RotatingFileHandler
app = Flask(__name__)
bootstrap = Bootstrap(app)


@app.route('/')
def index():
	return render_template('index.html')


@app.errorhandler(404)
def error_400(e):
	return render_template('error.html', error=404), 404


@app.errorhandler(500)
def error_500(e):
	return render_template('error.html', error=500), 500


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
	app.run(
		host=app.config['ip_address'],
		port=int(app.config['port']))
else:
	init(app)
	logs(app)
