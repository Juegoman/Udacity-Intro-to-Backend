Udacity Full Stack Nanodegree Project 3: Multi User Blog
--------------------------------------------------------

A website where you can create an account an create blog posts, view other user's blog posts, like them and comment on them.
Functionality for editing blog posts and comments is also present.

Passwords are hashed using bcrypt.

This web application is served using Google app engine. In order to run the project using app engine you need:
-a google app engine account
-Google App Engine Launcher
-the project files
-any dependencies
make sure that all of the project files are in the directory and that the dependencies are in the project root folder, then add the project to the App Engine Launcher.

Be sure to alter secret.py to protect the integrity of the cookie hashing functions.

After that the project should be able to run locally.

External dependencies:
-py-bcrypt (https://github.com/erlichmen/py-bcrypt)

drop bcrypt.py and blowfish.py from py-bcrypt into the root directory of the project and it should work.
