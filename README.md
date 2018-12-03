# Compound Lifts

![](report/resources/screenshots/home.png)

## Required Development Setup

* Use the following command to install all the dependencies from 'sourcecode/server/requirements.txt':

```sh
(Python 2.x) > pip install -r requirements.txt 
(Python 3.x) > pip3 install -r requirements.txt

```

## Usage

Once all of the dependencies have been installed:
* Create and setup a 'defaults.py' file in the config directory (example file included)
* Set current directory to <b>/sourcecode/</b>
* Set the Flask App: <b>$env:FLASK_APP="run.py"</b>
* Run the Server: <b>flask run</b>
* Setup complete! You should see the success message as shown in the image below
* Go to http://localhost:5000/ to access the site

![running]

## Screenshots

Sign Up and Login:

![](report/resources/screenshots/signup.png)
![](report/resources/screenshots/login.png)


Activity Feed:

![](report/resources/screenshots/activity_feed.png)

Athletes List and Search Interface:

![](report/resources/screenshots/athletes.png)

Athlete Pages:

![](report/resources/screenshots/profile.png)
![](report/resources/screenshots/profile_2.png)
![](report/resources/screenshots/profile_chart.png)
![](report/resources/screenshots/profile_training.png)
![](report/resources/screenshots/profile_followers.png)
![](report/resources/screenshots/profile_following.png)

Leaderboards:

![](report/resources/screenshots/leaderboards.png)

One Rep Max Calculator:

![](report/resources/screenshots/calculator.png)

Add / Edit / Delete Lifts:

![](report/resources/screenshots/edit_lifts.png)

Edit Profiles:

![](report/resources/screenshots/edit_profile.png)

Reset Password:

![](report/resources/screenshots/pw_reset.png)
![](report/resources/screenshots/pw_reset_email.png)

## Meta

Distributed under the [MIT license](https://choosealicense.com/licenses/mit/). See ``LICENSE`` for more information.

Author [@mcgill-a](https://github.com/mcgill-a)

<!-- Markdown link & img dfn's -->
[running]: https://i.imgur.com/keoeAmQ.png
