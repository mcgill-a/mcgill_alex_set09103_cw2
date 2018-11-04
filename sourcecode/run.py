from compoundlifts import app
import os

if __name__ == '__main__':
	random = os.urandom(24)
	app.secret_key = random
	app.run(
		host=app.config['ip_address'],
		port=int(app.config['port']))
else:
	print "__name__ != __main__"
	random = os.urandom(24)
	app.secret_key = random