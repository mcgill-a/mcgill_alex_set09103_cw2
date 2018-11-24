from flask import Flask, render_template, url_for, jsonify, request, redirect, session, flash
from flask_bootstrap import Bootstrap
from flask_pymongo import PyMongo
from bson.objectid import ObjectId
import ConfigParser, logging, os, json, random, re, string, datetime, bcrypt, urllib, hashlib, bson, math
from logging.handlers import RotatingFileHandler
from functools import wraps
from forms import SignupForm, LoginForm, RequestPasswordResetForm, ResetPasswordForm, EditAccount, EditProfile
from compoundlifts import app, mail, users, profiles, lifts 
from itsdangerous import TimedJSONWebSignatureSerializer as Serializer
from flask_mail import Message
from operator import itemgetter
from urllib2 import urlopen
from PIL import Image


@app.before_request
def before_request():
	# Log current time & IP address
	if session.get('logged_in'):
		current_datetime = datetime.datetime.now()
		ip = request.environ['REMOTE_ADDR']
		
		user = users.find_one({'_id' : ObjectId(session['id'])})
		user['last_seen'] = current_datetime
		user['last_ip'] = ip
		users.save(user)

@app.errorhandler(404)
def error_400(e):
	return render_template('error.html', error=404), 404


@app.errorhandler(500)
def error_500(e):
	return render_template('error.html', error=500), 500

@app.route('/', methods=['GET'])
def index():
	return render_template('index.html')


@app.route('/login', methods=['POST', 'GET'])
def login():
	if session.get('logged_in'):
		#output = "You are already logged in as " + session.get('email')
		#flash(output, 'warning')
		return redirect(url_for('index'))
	
	ip = request.environ['REMOTE_ADDR']
	form = LoginForm(request.form)
	if request.method =='POST' and form.validate():
		email = form.email.data
		password_entered = form.password.data

		result = users.find_one({'email' : re.compile(email, re.IGNORECASE)})

		if result is not None:
			if (bcrypt.checkpw(password_entered.encode('utf-8'), result['password'].encode('utf-8'))):

				session['logged_in'] = True
				session['email'] = result.get('email')
				session['id'] = str(result.get('_id'))
				session['fullname'] = result.get('first_name') + " " + result.get('last_name')
				#flash('You are now logged in', 'success')
				return redirect(url_for('index'))
				
			else:
				print "Failed login attempt |", email, "| IP:", ip
				error = "wrong_password"
				return render_template('login.html', form=form, error=error)
		else:
			error = "wrong_email"
			return render_template('login.html', form=form, error=error)
	return render_template('login.html', form=form)


@app.route('/signup', methods=['POST', 'GET'])
def signup():
	if session.get('logged_in'):
		#output = "You are already logged in as " + session.get('email')
		#flash(output, 'warning')
		return redirect(url_for('index'))
	
	form = SignupForm(request.form)
	if request.method == 'POST' and form.validate():
		# Set the user inputs
		# Force only the initial character in first name to be capitalised
		first_name = (form.firstname.data.lower()).capitalize()
		last_name = form.lastname.data
		email = form.email.data
		# Set the default inputs
		current_datetime = datetime.datetime.now()
		ip = request.environ['REMOTE_ADDR']
		account_level = 0
		followers = []
		following = []

		# Check if the email address already exists
		existing_user = users.find_one({'email' : re.compile(email, re.IGNORECASE)})

		if existing_user is not None:
			flash('Account already exists', 'danger')
			return render_template('signup.html', form=form)
		if existing_user is None:
			hashpass = bcrypt.hashpw(request.form['password'].encode('utf-8'), bcrypt.gensalt())
			users.insert({
				'first_name' : first_name,
				'last_name' : last_name,
				'email' : email,
				'password' : hashpass,
				'created' : current_datetime,
				'last_updated' : current_datetime,
				'last_seen' : current_datetime,
				'last_ip' : ip,
				'account_level' : account_level,
				'followers' : followers,
				'following' : following
			})

			# Retrieve the ID of the newly created user
			new_user = users.find_one({'email' : re.compile(email, re.IGNORECASE)})
			user_id = new_user['_id']

			# Setup the new user profile
			token = app.config['IP_INFO_TOKEN']
			url = 'https://ipinfo.io/json?token=' + token
			response = urlopen(url)
			ip_data = json.load(response)

			city= ip_data['city']
			country = ip_data['country']
			if country == 'GB':
				country = 'United Kingdom'
			elif country == 'US':
				country = 'United States of America'

			profile_pic = "default-profile.jpg"
			cover_pic = "default-cover.jpg"

			profiles.insert({
				'user_id' : user_id,
				'profile_pic' : profile_pic,
				'cover_pic' : cover_pic,
				'location_city' : city,
				'location_country' : country,
				'gender' : "",
				'dob' : "",
				'weight' : "",
				'profile_bio' : "",
				'current_program' : 
				{
					'name' : "",
					'date_started' : "",
					'desc' : "",
				}
			})
			print "INFO: New user has been created with email", email
			flash('Account registered', 'success')
        	return redirect(url_for('login'))
	else:
		return render_template('signup.html', form=form)


# Redirect logged out users with error message
def is_logged_in(f):
	@wraps(f)
	def wrap(*args, **kwargs):
		if 'logged_in' in session:
			return f(*args, **kwargs)
		else:
			flash('Access restricted. Please login first', 'danger')
			return redirect(url_for('login'))
	return wrap


@app.route('/logout')
def logout():
	if session.get('logged_in'):
		session.clear()
		#flash('You are now logged out', 'success')
		return redirect(url_for('index'))
	else:
		session.clear()
		return redirect(url_for('login'))


# Generate a password reset token that lasts 30 minutes
def get_reset_token(self, expires_sec=1800):
	s = Serializer(app.secret_key, expires_sec)
	return s.dumps({'_id' : str(self['_id'])}).decode('utf-8')


# Send an email containing the password reset token
def send_reset_email(user):
	token = get_reset_token(user)
	reset_url = url_for('reset_token', token=token, _external=True)

	subject = 'Compound Lifts | Password Reset Request'
	template = render_template('email.html', reset_url=reset_url, user=user)
	msg = Message(
		subject,
		sender='CompoundLiftsMail@gmail.com',
		recipients=[user['email']],
		html = template)

	mail.send(msg)


# Verify the password reset token is valid
def verify_reset_token(token):
	s = Serializer(app.secret_key)
	try:
		user_id = s.loads(token)['_id']
	except:
		return None
	return users.find_one({'_id' : ObjectId(user_id)})


@app.route('/reset_password/', methods=['POST', 'GET'])
def reset_request():
	if session.get('logged_in'):
		return redirect(url_for('index'))

	form = RequestPasswordResetForm()
	if request.method == 'POST' and form.validate():
		email = form.email.data
		user = users.find_one({'email' : re.compile(email, re.IGNORECASE)})
		
		if user is None:
			error = "wrong_email"
			return render_template('password_reset_request.html', form=form, error=error)
		else:
			print "Request password reset for ", email
			send_reset_email(user)
			flash('Password reset email has been sent!', 'info')
			return redirect(url_for('login'))

	return render_template('password_reset_request.html', form=form)


@app.route('/reset_password/<token>', methods=['POST', 'GET'])
def reset_token(token):
	if session.get('logged_in'):
		return redirect(url_for('index'))
	user = verify_reset_token(token)
	if user is None:
		flash('Invalid or expired reset token.', 'danger')
		return redirect(url_for('reset_request'))
	else:
		form = ResetPasswordForm()
		if request.method == 'POST' and form.validate():
			
			current_datetime = datetime.datetime.now()

			hashpass = bcrypt.hashpw(form.password.data.encode('utf-8'), bcrypt.gensalt())
			# Update the current user password
			user['password'] = hashpass
			user['last_updated'] = current_datetime
			users.save(user)
			
			print "INFO: Password Reset for", user['email']
			flash('Password has been reset!', 'success')
			return redirect(url_for('login'))

		return render_template('password_reset_form.html', form=form)


def athlete_name_search(search_query):
	matched = []
	for athlete in users.find():
		name = athlete['first_name'] + " " + athlete['last_name']
		if search_query.lower() in name.lower():
			matched.append(athlete)

	return matched


def add_extras(athletes):
	output = []
	for current in athletes:
		current_profile = None
		current_profile = profiles.find_one({'user_id' : current['_id']})
		if current_profile is not None:
			current['city'] = current_profile['location_city']
			current['country'] = current_profile['location_country']
			if 'profile_pic' in current_profile and 'cover_pic' in current_profile:
				current_profile['profile_pic'] = url_for('static', filename='resources/users/profile/' + current_profile['profile_pic'])
				current_profile['cover_pic'] = url_for('static', filename='resources/users/cover/' + current_profile['cover_pic'])
				
				current['profile_pic'] = current_profile['profile_pic']
				current['cover_pic'] = current_profile['cover_pic']
		output.append(current)
	return output


@app.route('/athletes/')
def athletes(id=None):
	current_user = None
	search_match = False

	if session.get('logged_in'):
		current_user = users.find_one({'_id' : ObjectId(session.get('id'))})

	args = request.args.to_dict()
	if 'name' in args and len(args['name']) > 0:
		search_query = args['name']
		athletes = athlete_name_search(search_query)
		search_match = True
	else:
		athletes = users.find().limit(10)
	
	display = add_extras(athletes)

	if search_match:
		return render_template('athletes.html', athletes=display, current_user=current_user, search_query=search_query)
	else:
		return render_template('athletes.html', athletes=display, current_user=current_user)


def add_comment_extras(user_lifts):
	# Inject the user profile picture and full name of each commenter to the lift comments
	for lift_type in user_lifts['lifts']:
		if len(user_lifts['lifts'][lift_type]) >= 1:
			for index, lift in enumerate(user_lifts['lifts'][lift_type]):
				if 'comments' in user_lifts['lifts'][lift_type][index]:
					for current_comment in user_lifts['lifts'][lift_type][index]['comments']:
						commenter_user = users.find_one({'_id' : current_comment['user_id']})
						commenter_profile = profiles.find_one({'user_id' : current_comment['user_id']})

						current_comment['profile_pic'] = url_for('static', filename='resources/users/profile/' + commenter_profile['profile_pic'])
						current_comment['full_name'] = commenter_user['first_name'] + " " + commenter_user['last_name']
						date = datetime.datetime.strptime(str(current_comment['date']), '%Y-%m-%d %H:%M:%S.%f')
						date = date.strftime("%B %d, %Y")
						current_comment['date'] = date
		
	return user_lifts


@app.route('/athletes/<id>')
def athlete(id=None):
	current_user = None
	if session.get('logged_in'):
		current_user = users.find_one({'_id' : ObjectId(session.get('id'))})
	
	if id is not None and bson.objectid.ObjectId.is_valid(id):
		athlete = users.find_one({'_id' : ObjectId(id)})

		if athlete is not None:

			user_lifts = lifts.find_one({'user_id' : ObjectId(id)})
			
			deadlift_max = None
			bench_max = None
			squat_max = None

			if user_lifts is not None:
				if 'deadlift' in user_lifts['lifts'] and len(user_lifts['lifts']['deadlift']) >= 1 :
					deadlift_max = findMaxLift(user_lifts['lifts']['deadlift'])
				
				if 'bench' in user_lifts['lifts'] and len(user_lifts['lifts']['bench']) >= 1 :
					bench_max = findMaxLift(user_lifts['lifts']['bench'])

				if 'squat' in user_lifts['lifts'] and len(user_lifts['lifts']['squat']) >= 1 :
					squat_max = findMaxLift(user_lifts['lifts']['squat'])

			user_profile = profiles.find_one({'user_id' : ObjectId(id)})
			profile_pic_path = url_for('static', filename='resources/users/profile/' + user_profile['profile_pic'])
			cover_pic_path = url_for('static', filename='resources/users/cover/' + user_profile['cover_pic'])

			following = []
			followers = []

			for current_id in athlete['followers']:
				current = users.find_one({'_id' : ObjectId(current_id)})
				followers.append(current)

			for current_id in athlete['following']:
				current = users.find_one({'_id' : ObjectId(current_id)})
				following.append(current)

			followers = add_extras(followers)
			following = add_extras(following)

			if user_lifts is not None:
				user_lifts = add_comment_extras(user_lifts)

			updated_age = -1
			if user_profile['dob']:
				updated_age = math.floor(((datetime.datetime.utcnow() - user_profile['dob']).days) / 365)
				updated_age = int(updated_age)
			
			# Convert raw input line breaks to html line breaks
			if 'desc' in user_profile['current_program']:
				user_profile['current_program']['desc'] = user_profile['current_program']['desc'].replace('\n', '<br>')

			# Convert the raw date input to a nice and readable date format
			if user_profile['current_program']['date_started'] is not None:				
				
				date = datetime.datetime.strptime(str(user_profile['current_program']['date_started']), '%Y-%m-%d %H:%M:%S')
				date = date.strftime("%B %d, %Y")
				user_profile['current_program']['date_started'] = date
			
			history = {}

			# Lift Weight Track Chart
			for lift_type in user_lifts['lifts']:
				data = user_lifts['lifts'][lift_type]
				for current in data:
					extract = {
						'date' : current['date'],
						'weight' : int(current['weight'])
					}
					if lift_type not in history:
						history[lift_type] = [extract]
					else:
						history[lift_type].append(extract)
			
			#history_deadlift = history['deadlift']
			#history_bench = history['bench']
			#history_squat = history['squat']

			history['deadlift'].sort(key=lambda item:item['date'], reverse=False)
			history['bench'].sort(key=lambda item:item['date'], reverse=False)
			history['squat'].sort(key=lambda item:item['date'], reverse=False)

			return render_template('athlete.html', athlete=athlete, user_lifts=user_lifts, user_profile=user_profile, profile_pic=profile_pic_path, cover_pic=cover_pic_path, deadlift_max=deadlift_max, bench_max=bench_max, squat_max=squat_max, current_user=current_user, followers=followers, following=following, updated_age=updated_age, history=history)
		else:
			flash('Athlete not found', 'danger')
			return redirect(url_for('athletes'))
	flash('Invalid Athlete ID entered', 'danger')
	return redirect(url_for('athletes'))


def findMaxLift(lifts):
	maxWeight = 0
	maxLift = None

	for current in lifts:
		if current['weight'] > maxWeight:
			maxWeight = current['weight']
			maxLift = current
	return maxLift


@app.route('/athletes/edit/lifts', methods=['POST', 'GET'])
@is_logged_in
def athlete_edit_lifts():
	current_user = None
	if session.get('logged_in'):
		current_user = users.find_one({'_id' : ObjectId(session.get('id'))})
	else:
		flash('Access restricted. Please login first', 'danger')
		return redirect(url_for('login'))
	
	id = str(current_user['_id'])
	if id is not None and bson.objectid.ObjectId.is_valid(id):
		athlete = users.find_one({'_id' : ObjectId(id)})
		user_lifts = lifts.find_one({'user_id' : ObjectId(id)})
		
		deadlift = []
		bench = []
		squat = []

		if user_lifts is not None:
			if "deadlift" in user_lifts['lifts']:
				deadlift = user_lifts['lifts']['deadlift']
			if "bench" in user_lifts['lifts']:
				bench = user_lifts['lifts']['bench']
			if "squat" in user_lifts['lifts']:
				squat = user_lifts['lifts']['squat']
		
		if athlete is not None:
			if str(current_user['_id']) == id: # or current_user['account_level'] == 10 (to let admin modify user profile/lifts/account)

				return render_template('edit-lifts.html', athlete=athlete, current_user=current_user, deadlifts=deadlift, bench=bench, squat=squat)
			else:
				flash("Access restricted. You do not have permission to do that", 'danger')
				return redirect(url_for('athletes'))
	flash('Invalid Athlete ID', 'danger')
	return redirect(url_for('athletes'))

@app.route('/athletes/edit/account', methods=['POST', 'GET'])
@is_logged_in
def athlete_edit_account():
	current_user = None
	if session.get('logged_in'):
		current_user = users.find_one({'_id' : ObjectId(session.get('id'))})
	else:
		flash('Access restricted. Please login first', 'danger')
		return redirect(url_for('login'))
	
	account_form = EditAccount(request.form)
	id = str(current_user['_id'])
	if id is not None and bson.objectid.ObjectId.is_valid(id):
		athlete = users.find_one({'_id' : ObjectId(id)})		
				
		if athlete is not None:
			if str(current_user['_id']) == id: # (disabled) or current_user['account_level'] == 10
				#profile_pic = url_for('static', filename="resources/users/profile" + current_user['use'])

				if request.method == 'POST' and account_form.validate():
					email = account_form.email.data
					# Check if the email address already exists
					existing_user = users.find_one({'email' : re.compile(email, re.IGNORECASE)})

					if existing_user is not None and existing_user != current_user:
						flash('Account already exists', 'danger')
						return redirect('athletes/edit/')
					else:

						current_user['first_name'] = account_form.firstname.data
						current_user['last_name'] = account_form.lastname.data
						current_user['email'] = account_form.email.data

						users.save(current_user)
						session['email'] = current_user['email']
						session['fullname'] = current_user['first_name'] + " " + current_user['last_name']

					flash("Your account has been updated", "success")
					return redirect('athletes/edit/account')

				elif request.method == 'GET':
					account_form.firstname.data = current_user['first_name']
					account_form.lastname.data = current_user['last_name']
					account_form.email.data = current_user['email']

				return render_template('edit-account.html', athlete=athlete, current_user=current_user, account_form=account_form)
			else:
				flash("Access restricted. You do not have permission to do that", 'danger')
				return redirect(url_for('athletes'))
	flash('Invalid Athlete ID', 'danger')
	return redirect(url_for('athletes'))


def store_profile_pic(form_pic, profile_user_id):
	_, ext = os.path.splitext(form_pic.filename)
	picture_fn = profile_user_id + ext
	picture_path = os.path.join(app.root_path, 'static/resources/users/profile', picture_fn)
	
	# Set the image width and height to reduce large image file sizes
	file_size = (200, 200)
	img = Image.open(form_pic)
	img.thumbnail(file_size)

	img.save(picture_path)

	return picture_fn

def store_cover_pic(form_pic, profile_user_id):
	_, ext = os.path.splitext(form_pic.filename)
	picture_fn = profile_user_id + ext
	picture_path = os.path.join(app.root_path, 'static/resources/users/cover', picture_fn)

	form_pic.save(picture_path)

	return picture_fn

@app.route('/athletes/edit/', methods=['POST', 'GET'])
@app.route('/athletes/edit/profile', methods=['POST', 'GET'])
@is_logged_in
def athlete_edit_profile():
	current_user = None
	if session.get('logged_in'):
		current_user = users.find_one({'_id' : ObjectId(session.get('id'))})
	else:
		flash('Access restricted. Please login first', 'danger')
		return redirect(url_for('login'))
	
	profile_form = EditProfile()
	id = str(current_user['_id'])
	if id is not None and bson.objectid.ObjectId.is_valid(id):
		athlete = users.find_one({'_id' : ObjectId(id)})
		user_profile = profiles.find_one({'user_id' : ObjectId(session.get('id'))})

		if str(current_user['_id']) == id:
			if request.method == 'POST' and profile_form.validate():
				# Convert date of birth and program start date to DateTime objects
				dob = None
				if profile_form.dob.data is not None:
					dob = datetime.datetime.combine(profile_form.dob.data, datetime.time.min)
				date_started = None
				if profile_form.program_start_date.data is not None:
					date_started = datetime.datetime.combine(profile_form.program_start_date.data, datetime.time.min)
				
				# Capitalise first letter of each word
				city = profile_form.city.data.title()
				country = profile_form.country.data.title()
				# Replace multiple spaces and trailing space
				city = ' '.join(city.split())
				country = ' '.join(country.split())
				
				profile_pic = "default-profile.jpg"
				cover_pic = "default-cover.jpg"
				
				# If a file was provided by the user then upload and store it
				# Then store the name of the new file in the user profile DB
				if profile_form.profile_pic.data:
					profile_pic = store_profile_pic(profile_form.profile_pic.data, str(user_profile['user_id']))
				
				if profile_form.cover_pic.data:
					cover_pic = store_cover_pic(profile_form.cover_pic.data, str(user_profile['user_id']))

				# Create profile dictionary				
				profile = {
					'user_id' : ObjectId(id),
					'profile_pic' : profile_pic,
					'cover_pic' : cover_pic,
					'location_city' : city,
					'location_country' : country,
					'gender' : profile_form.gender.data,
					'dob' : dob,
					'weight' : profile_form.weight.data,
					'profile_bio' : profile_form.bio.data,
					'current_program' : 
					{
						'name' : profile_form.program_name.data,
						'date_started' : date_started,
						'desc' : profile_form.program_desc.data,
					}
				}
						
				if user_profile is None:
					profiles.insert(profile)
				else:
					if profile_form.profile_pic.data:
						user_profile['profile_pic'] = profile['profile_pic']
					if profile_form.cover_pic.data:
						user_profile['cover_pic'] = profile['cover_pic']
					user_profile['profile_bio'] = profile['profile_bio']
					user_profile['location_city'] = profile['location_city']
					user_profile['location_country'] = profile['location_country']
					user_profile['gender'] = profile['gender']
					user_profile['dob'] = profile['dob']
					user_profile['weight'] = profile['weight']
					user_profile['current_program'] = profile['current_program']
					profiles.save(user_profile)

				flash("Your account has been updated", "success")
				return redirect('athletes/edit/profile')

			elif request.method == 'GET' and user_profile is not None:
				profile_form.profile_pic.data = ""
				profile_form.cover_pic.data = ""
				profile_form.city.data = user_profile['location_city']
				profile_form.country.data = user_profile['location_country']
				profile_form.gender.data = user_profile['gender']
				profile_form.dob.data = user_profile['dob']
				profile_form.weight.data = user_profile['weight']
				profile_form.bio.data = user_profile['profile_bio']
				profile_form.program_name.data = user_profile['current_program']['name']
				profile_form.program_start_date.data = user_profile['current_program']['date_started']
				profile_form.program_desc.data = user_profile['current_program']['desc']

			
			return render_template('edit-profile.html', athlete=athlete, current_user=current_user, profile_form=profile_form)
		else:
			flash("Access restricted. You do not have permission to do that", 'danger')
			return redirect(url_for('athletes'))

	flash('Invalid Athlete ID', 'danger')
	return redirect(url_for('athletes'))


@app.route('/lifts/add/<lift>', methods=['POST', 'GET'])
@is_logged_in
def add_lift(lift=None):
	if request.method == 'POST' and request.data:
		response = request.data
		data = json.loads(response)

		original_url = data['video_url']
		embed_url = original_url.replace("watch?v=", "embed/")
		data['embed_url'] = embed_url
		data['date_added'] = datetime.datetime.now()
		# Check if user already exists in lifts table
		user_lifts = lifts.find_one({'user_id' : ObjectId(session.get('id'))})
		if user_lifts is None:
			lifts.insert(
			{
				'user_id' : ObjectId(session.get('id')),
				'lifts' :  {lift : [ data ] }
			})
		else:
			# If key is not in the list then add it
			if lift in user_lifts['lifts']:
				current_lift = user_lifts['lifts'][lift]
				if data['action'] == "add":
					current_lift.append(data)
				elif data['action'] == "edit":
					lift_index = int(data['index'])
					# Update the lift at the current index
					current_lift[lift_index]['date'] = data['date']
					current_lift[lift_index]['weight'] = data['weight']
					current_lift[lift_index]['video_url'] = data['video_url']
					current_lift[lift_index]['description'] = data['description']
					current_lift[lift_index]['embed_url'] = data['video_url'].replace("watch?v=", "embed/")
				# Sort the current list of lifts by date (most recent first)
				sorted_lift = sorted(current_lift, key=itemgetter('date'), reverse=True)
				user_lifts['lifts'][lift] = sorted_lift
				lifts.save(user_lifts)
			else:
				user_lifts['lifts'][lift] = [ data ]
				lifts.save(user_lifts)	
	
		return response
	return redirect(url_for('index'))


@app.route('/lifts/remove/<lift>', methods=['POST', 'GET'])
@is_logged_in
def remove_lift(lift=None):
	if request.method == 'POST' and request.data:
		lift_id = request.data
		# Check if user already exists in lifts table
		user_lifts = lifts.find_one({'user_id' : ObjectId(session.get('id'))})
		if user_lifts is not None:
			del user_lifts['lifts'][lift][int(lift_id)]
			lifts.save(user_lifts)
			print "Removed", lift, "from DB"
		return lift_id
	return redirect(url_for('index'))


@app.route('/follow/', methods=['POST', 'GET'])
@is_logged_in
def follow():
	if request.method == 'POST' and request.data:
		id_to_follow = request.data
		account_follow = users.find_one({'_id' : ObjectId(id_to_follow)})
		if account_follow is not None:
			# Update the current user 'following' list (add)
			users.update({'_id' : ObjectId(session.get('id'))}, {
				'$addToSet' : {'following': id_to_follow}
				})
			# Update the other persons 'followers' list (add)
			users.update({'_id' : ObjectId(id_to_follow)}, {
				'$addToSet' : {'followers': session.get('id')}
				})
			return id_to_follow
	return redirect(url_for('index'))


@app.route('/unfollow/', methods=['POST', 'GET'])
@is_logged_in
def unfollow():
	if request.method == 'POST' and request.data:
		id_to_unfollow = request.data
		account_follow = users.find_one({'_id' : ObjectId(id_to_unfollow)})
		if account_follow is not None:
			# Update the current user 'following' list (remove)
			users.update({'_id' : ObjectId(session.get('id'))}, {
				'$pull' : {'following': id_to_unfollow}
				})
			# Update the other persons 'followers' list (remove)
			users.update({'_id' : ObjectId(id_to_unfollow)}, {
				'$pull' : {'followers': session.get('id')}
				})
			return id_to_unfollow
	return redirect(url_for('index'))


@app.route('/comment/add', methods=['POST', 'GET'])
@is_logged_in
def comment_add():
	if request.method == 'POST' and request.data:
		data = request.data
		data = data.encode('utf-8')
		data = json.loads(data)
		
		athlete_id = data['athlete_id']
		commenter_id = data['commenter_id']
		comment = data['comment']
		lift_type = data['lift_type']
		lift_index = data['lift_index']

		# Make sure user exists in lifts table
		user_lifts = lifts.find_one({'user_id' : ObjectId(athlete_id)})
		if user_lifts is not None:

			current_datetime = datetime.datetime.now()

			new_comment = {
				'user_id' : ObjectId(commenter_id),
				'comment' : comment,
				'date' : current_datetime
			}
			if 'comments' in user_lifts['lifts'][lift_type][int(lift_index)]:
				user_lifts['lifts'][lift_type][int(lift_index)]['comments'].append(new_comment)
			else:
				user_lifts['lifts'][lift_type][int(lift_index)]['comments'] = [new_comment]
			lifts.save(user_lifts)
			print commenter_id, "added a new comment on", lift_type, lift_index

		return str(data)
	return redirect(url_for('index'))


@app.route('/comment/delete', methods=['POST', 'GET'])
@is_logged_in
def comment_remove():
	if request.method == 'POST' and request.data:
		data = request.data
		data = data.encode('utf-8')
		data = json.loads(data)
		
		athlete_id = data['athlete_id']
		commenter_id = data['commenter_id']
		lift_type = data['lift_type']
		lift_index = data['lift_index']
		comment_index = data['comment_index']

		# Make sure user exists in lifts table
		user_lifts = lifts.find_one({'user_id' : ObjectId(athlete_id)})
		if user_lifts is not None:

			if 'comments' in user_lifts['lifts'][lift_type][int(lift_index)]:
				user_lifts['lifts'][lift_type][int(lift_index)]['comments'].pop(comment_index)
			lifts.save(user_lifts)
			print commenter_id, "removed a comment on", lift_type, lift_index, comment_index
		return str(data)
	return redirect(url_for('index'))


@app.route('/comment/edit', methods=['POST', 'GET'])
@is_logged_in
def comment_edit():
	if request.method == 'POST' and request.data:
		data = request.data
		data = data.encode('utf-8')
		data = json.loads(data)
		
		athlete_id = data['athlete_id']
		commenter_id = data['commenter_id']
		comment = data['comment']
		lift_type = data['lift_type']
		lift_index = data['lift_index']
		comment_index = data['comment_index']

		# Make sure user exists in lifts table
		user_lifts = lifts.find_one({'user_id' : ObjectId(athlete_id)})
		if user_lifts is not None:

			if 'comments' in user_lifts['lifts'][lift_type][int(lift_index)]:
				user_lifts['lifts'][lift_type][int(lift_index)]['comments'][comment_index] = comment
			lifts.save(user_lifts)
			print commenter_id, "edited a comment on", lift_type, lift_index, comment_index
		return str(data)
	return redirect(url_for('index'))


@app.route('/calculator', methods=['GET'])
def calculator():
	return render_template('calculator.html')


@app.route('/leaderboards', methods=['GET'])
def leaderboards():
	all_lifts = []
	cursor = lifts.find({})

	for document in cursor:
		current_id =  document['user_id']
		user = users.find_one({'_id' : current_id})
		full_name = user['first_name'] + " " + user['last_name']
		for lift_type in document['lifts']:
			for lift in document['lifts'][lift_type]:
				if lift_type == "bench":
					lift_type = "Bench Press"
				elif lift_type =="squat":
					lift_type = "Barbell Squat"
				lift['type'] = lift_type.title()
				lift['full_name'] = full_name
				lift['athlete_id'] = current_id
				all_lifts.append(lift)
	
	return render_template('leaderboards.html', all_lifts=all_lifts)


def add_feed_extras(feed):
	
	for lift in feed:
		# Insert additonal comment information (profile pic, full name, nice date)
		if 'comments' in lift:
			for current_comment in lift['comments']:
				commenter_user = users.find_one({'_id' : current_comment['user_id']})
				commenter_profile = profiles.find_one({'user_id' : current_comment['user_id']})

				current_comment['profile_pic'] = url_for('static', filename='resources/users/profile/' + commenter_profile['profile_pic'])
				current_comment['full_name'] = commenter_user['first_name'] + " " + commenter_user['last_name']

				current_comment['date'] = current_comment['date'].strftime("%B %d, %Y")
	
		# Convert date added to a more readable value to display
		date = datetime.datetime.strptime(str(lift['date_added']), '%Y-%m-%d %H:%M:%S.%f')
		date = date.strftime("%B %d, %Y")
		lift['date_added'] = date

		# Convert lift type to offical lift name
		lift_type = lift['original_type']
		if lift_type == "bench":
			lift_type = "Bench Press"
		elif lift_type == "squat":
			lift_type = "Barbell Squat"
		lift['lift_type'] = lift_type.title()

	return feed


@app.route('/feed', methods=['GET'])
@is_logged_in
def feed():
	feed = []
	current_user = users.find_one({'_id' : ObjectId(session.get('id'))})
	if current_user is not None:

		following_count = len(current_user['following'])
		# Add their own lifts to the feed as well
		current_user['following'].append(current_user['_id'])
		for athlete in current_user['following']:
			athlete_user = users.find_one({'_id' : ObjectId(athlete)})
			athlete_profile = profiles.find_one({'user_id' : ObjectId(athlete)})
			athlete_lifts = lifts.find_one({'user_id' : ObjectId(athlete)})
			if athlete_lifts is not None:
				for lift_type in athlete_lifts['lifts']:
					for index, lift in enumerate(athlete_lifts['lifts'][lift_type]):
						lift['user_id'] = ObjectId(athlete)
						lift['lift_index'] = index
						# Compare current lift weight with overall lift PB
						if lift['weight'] == athlete_lifts['lifts'][lift_type][0]['weight']:
							# If there is more than 1 lift, make sure it is a higher weight than 2nd lift
							if len(athlete_lifts['lifts'][lift_type]) > 1:
								if lift['weight'] > athlete_lifts['lifts'][lift_type][1]['weight']:
									lift['pb'] = True
								else:
									lift['pb'] = False
							else:
								lift['pb'] = True
						else:
							lift['pb'] = False
						lift['original_type'] = lift_type
						lift['full_name'] = athlete_user['first_name'] + " " + athlete_user['last_name']
						feed.append(lift)
						lift['profile_pic'] = url_for('static', filename='resources/users/profile/' + athlete_profile['profile_pic'])
		# Sort the list by most recently added (descending)
		feed.sort(key=lambda item:item['date_added'], reverse=True)
		# Add additional fields needed in the template
		feed = add_feed_extras(feed)

		return render_template('feed.html', following_count=following_count, feed=feed, current_user=current_user)
	else:
		return render_template('feed.html')


@app.route('/chart', methods=['GET'])
def chart():
	id = "5bf1b42b524d47131c5e59d7"
	user_lifts = lifts.find_one({'user_id' : ObjectId(id)}) 
	data = user_lifts['lifts']['deadlift']
	history = []

	dates = []
	weights = []

	for current in data:
		extract = {
			'date' : current['date'],
			'weight' : int(current['weight'])
		}
		print extract
		history.append(extract)

	history.sort(key=lambda item:item['date'], reverse=False)

	if history != None:
		return render_template('chart.html', history=history)
	return render_template('chart.html')