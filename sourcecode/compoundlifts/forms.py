from flask_wtf import FlaskForm
from wtforms import StringField, SelectField, TextAreaField, PasswordField, IntegerField , validators, DateField, DecimalField

class LoginForm(FlaskForm):
	email = StringField('email', [validators.Email()])
	password = PasswordField('password', [
		validators.Length(min=8, max=50)
	])


class SignupForm(FlaskForm):
	firstname = StringField('firstname', [
		validators.Length(min=2, max=50),
		validators.Regexp('^\\w+$', message="First name may only contain letters")
		])
	lastname = StringField('lastname', [
		validators.Length(min=2, max=50),
		validators.Regexp('^\\w+$', message="Last name may only contain letters")
		])
	email = StringField('email', [validators.Email()])
	password = PasswordField('password', [
		validators.DataRequired(),
		validators.Length(min=8, max=50),
		validators.EqualTo('confirm', message='Passwords do not match')
	])
	confirm = PasswordField('confirm')

class RequestPasswordResetForm(FlaskForm):
	email = StringField('email', [validators.Email()])


class ResetPasswordForm(FlaskForm):
	password = PasswordField('password', [
		validators.DataRequired(),
		validators.Length(min=8, max=50),
		validators.EqualTo('confirm', message='Passwords do not match')
	])
	confirm = PasswordField('confirm')

class EditAccount(FlaskForm):
	firstname = StringField('firstname', [
		validators.Length(min=2, max=50),
		validators.Regexp('^\\w+$', message="First name may only contain letters")
		])
	lastname = StringField('lastname', [
		validators.Length(min=2, max=50),
		validators.Regexp('^\\w+$', message="Last name may only contain letters")
		])
	email = StringField('email', [validators.Email()])

class EditProfile(FlaskForm):
	city = StringField('city')
	country = StringField('city')
	gender = SelectField('Gender', choices=[('', 'Select'), ('male', 'Male'), ('female', 'Female')])
	dob = DateField('dob', [validators.optional()])
	weight = IntegerField('weight', [
		validators.optional()
		])
	bio = TextAreaField('bio')
	program_name = StringField('program-name')
	program_start_date = DateField('program-start-date', [validators.optional()])
	program_desc = TextAreaField('program-desc')