import os
import webapp2
import jinja2
import re

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir),
                               autoescape = True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class MainHandler(Handler):
    def get(self):
        self.render("main.html")
    def post(self):
        text = self.request.get('text')
        encrypted_text = apply_ROT13(str(text))
        self.render("main.html", text = encrypted_text)

class SigninHandler(Handler):
    def get(self):
        self.render("signin.html")
    def post(self):
        user_username = str(self.request.get("username"))
        user_pass = str(self.request.get("password"))
        pass_verify = str(self.request.get("verify"))
        user_email = str(self.request.get("email"))

        username = valid_username(user_username)
        password = valid_password(user_pass)
        verify = pass_match(user_pass, pass_verify)
        email = valid_email(user_email)

        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        if not (username and password and verify and email):
            if not username:
                username_error = "That's not a valid username."
            if not password:
                password_error = "That wasn't a valid password."
            elif not verify:
                verify_error = "Your passwords didn't match."
            if not email:
                email_error = "That's not a valid email."
            self.render("signin.html", username = user_username,
                                       username_error = username_error,
                                       password_error = password_error,
                                       verify_error = verify_error,
                                       email = user_email,
                                       email_error = email_error)
        else:
            self.redirect("/welcome?username=%s" % user_username)

class WelcomeHandler(Handler):
    def get(self):
        username = str(self.request.get("username"))
        self.render("welcome.html", username = username)

app = webapp2.WSGIApplication([
    ('/', MainHandler),
    ("/signin", SigninHandler),
    ("/welcome", WelcomeHandler)
], debug=True)

# Helper functions
def apply_ROT13(text):
    return text.encode('rot_13')

USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
PASS_RE = re.compile(r"^.{3,20}$")
EMAIL_RE = re.compile(r"^[\S]+@[\S]+.[\S]+$")

def valid_username(username):
    return USER_RE.match(username)
def valid_password(password):
    return PASS_RE.match(password)
def pass_match(password, verify):
    return password == verify
def valid_email(email):
    return EMAIL_RE.match(email) or not email
