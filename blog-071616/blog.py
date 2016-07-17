import os
import webapp2
import jinja2
import re
import bcrypt
import hashlib
import hmac
import cgi
# secret module contains a function secret(), which returns a secret string
import secret

from google.appengine.ext import db

# jinja2 initialization
template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader=jinja2.FileSystemLoader(template_dir),
                               autoescape=True)


# jinja2 template base class
class Handler(webapp2.RequestHandler):

    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))


# Post model
class Post(db.Model):
    author = db.StringProperty(required=True)
    subject = db.StringProperty(required=True)
    content = db.TextProperty(required=True)
    created = db.DateTimeProperty(auto_now_add=True)
    likes = db.IntegerProperty(required=True)
    comments = db.TextProperty()

    # content formatting for newline escaping
    def format(self):
        output = cgi.escape(self.content)
        output = output.replace('\n', '<br>')
        return output

    # a function that returns the number of likes on a post casted into a str
    def str_likes(self):
        return str(self.likes)

    # Comments are defined in the text property as a serialized text of format:
    # |hash1~author1~comment1|hash2~author2~comment2|hash3~author3~comment3|...
    #
    # add_comment(author, comment): adds a comment to the serialized text and
    # updates the database. Returns the new serialized text.
    def add_comment(self, author, comment):
        comment_hash = str(hashlib.md5(author + comment).hexdigest())
        if not self.comments:
            self.comments = '|' + comment_hash + '~' + author + '~' + comment
        else:
            self.comments = self.comments + '|' + comment_hash + '~' + author \
                            + '~' + comment
        self.put()
        return self.comments
    # listify_comments(): returns a list of (hash, author, comment) pairs.

    def listify_comments(self):
        if not self.comments:
            return None
        else:
            frst_split = str(self.comments).split('|')
            del frst_split[0]
            l_comm = []
            for comment in frst_split:
                l_comm.append(comment.split('~'))
        return l_comm
    # del_from_list_comments(l_comm, index): deletes a (author, comment)
    # pair from l_comm list at index. Returns the updated comment list.

    def del_from_list_comments(self, l_comm, index):
        if not l_comm:
            return None
        if index < 0 or index >= len(l_comm):
            return l_comm
        else:
            del l_comm[index]
            return l_comm
    # edit_from_list_comments(l_comm, index, new_comm): edits the comment of
    # a (author, comment) pair from l_comm list at index.
    # Returns the updated comment list.

    def edit_from_list_comments(self, l_comm, index, new_comm):
        if not l_comm:
            return None
        if index < 0 or index >= len(l_comm):
            return l_comm
        else:
            l_comm[index][2] = new_comm
            return l_comm
    # serialize_list_comments(l_comm): serializes l_comm back into the storage
    # format and updates the database. Returns the new serialized text.

    def serialize_list_comments(self, l_comm):
        if not l_comm:
            self.comments = None
            self.put()
            return None
        else:
            frst_join = []
            for comment in l_comm:
                frst_join.append('~'.join(comment))
            result = '|'.join(frst_join)
            self.comments = '|' + result
            self.put()
            return self.comments
    # comment_len(): returns the number of comments.

    def comment_len(self):
        l_comm = self.listify_comments()
        if not l_comm:
            return 0
        else:
            return len(l_comm)


# User model
class User(db.Model):
    username = db.StringProperty(required=True)
    password_hash = db.TextProperty(required=True)
    email = db.StringProperty()
    liked = db.TextProperty()

    # function for verifying that a post has been liked by a user or not
    def post_id_in_liked(self, p_id):
        return str(p_id) in str(self.liked)


class MainPage(Handler):

    # helper function for rendering the front page.
    def render_front(self, error=""):
        posts = db.GqlQuery("SELECT * FROM Post ORDER BY created DESC")
        u = verify_cookie(self)
        if u:
            # user is logged in, serve front page with features
            self.render("loggedinfront.html", posts=posts,
                        u=u,
                        error=error)
        else:
            # guest is served reduced front page.
            self.render("front.html", posts=posts, u=u, error=error)

    def get(self):
        self.render_front()

    # posting for likes
    def post(self):
        post_id = self.request.get("post_id")
        post = Post.get_by_id(int(post_id))
        u = verify_cookie(self)
        if u:
            if post.author != u.username:
                like(post, u)
                self.redirect("/waitredir/1/front")
            else:
                self.render_front("You can't like your own posts!")
        else:
            self.render_front("You need to be logged in for that!")


class SubmitPage(Handler):

    # helper function for displaying the submission page
    def render_submit(self, subject="", content="", error=""):
        self.render("newpost.html", subject=subject,
                    content=content,
                    error=error)

    # check to see if the user is logged in before serving the submission page.
    def get(self):
        u = verify_cookie(self)
        if u:
            self.render_submit()
        else:
            self.redirect("/login")

    # create a Post with this post
    def post(self):
        u = verify_cookie(self)
        if u:
            author = u.username
            subject = self.request.get("subject")
            content = self.request.get("content")

            if subject and content:
                p = Post(author=author,
                         subject=subject,
                         content=content,
                         likes=0)
                p.put()

                self.redirect("/" + str(p.key().id()))
            else:
                error = "Please input both a subject and content."
                self.render_submit(subject, content, error)
        else:
            self.redirect("/login")


class EditComment(Handler):

    # function gets the post and the hash of the selected comment and serves
    # the corresponding edit page
    def get(self, post_id, comment_hash):
        u = verify_cookie(self)
        post = Post.get_by_id(int(post_id))
        comments = post.listify_comments()
        for c in comments:
            if c[0] == comment_hash:
                author = c[1]
                comment = c[2]
                break
        if u and author in u.username:
            if comment:
                self.render("editcomm.html", comment=comment,
                            post=post,
                            error="")
            else:
                self.redirect("/" + post_id)
        else:
            self.redirect("/login")

    # depending on whether the user chooses to edit or delete the comment this
    # function performs the corresponding action
    def post(self, post_id, comment_hash):
        u = verify_cookie(self)
        post = Post.get_by_id(int(post_id))
        comments = post.listify_comments()
        for c in comments:
            if c[0] == comment_hash:
                comment_index = comments.index(c)
                author = c[1]
                break
        if u and author in u.username:
            intent = self.request.get("intent")
            comment = self.request.get("comment")
            if "delete" in intent:
                comments = post.del_from_list_comments(comments, comment_index)
                post.serialize_list_comments(comments)
                self.redirect("/waitredir/1/" + post_id)
            else:
                if comment:
                    comments = post.edit_from_list_comments(comments,
                                                            comment_index,
                                                            comment)
                    post.serialize_list_comments(comments)
                    self.redirect("/waitredir/1/" + post_id)
                else:
                    error = "Please enter a comment."
                    self.render("editcomm.html", comment=comment,
                                post=post,
                                error=error)
        else:
            self.redirect("/login")


class EditPage(Handler):

    # helper function for rendering the edit page
    def render_edit(self, subject="", content="", error=""):
        self.render("edit.html", subject=subject,
                    content=content,
                    error=error)

    # check to see if the user has permission to edit this post and serve the
    # appropriate page.
    def get(self, post_id):
        u = verify_cookie(self)
        post = Post.get_by_id(int(post_id))
        if u and post.author in u.username:
            self.render_edit(subject=post.subject, content=post.content)
        else:
            self.redirect("/login")

    # depending on whether the user chooses to edit or delete the post this
    # function performs the corresponding action
    def post(self, post_id):
        u = verify_cookie(self)
        post = Post.get_by_id(int(post_id))
        if u and post.author in u.username:
            subject = self.request.get("subject")
            content = self.request.get("content")
            intent = self.request.get("intent")
            if "delete" in intent:
                users = User.gql("")
                for user in users:
                    if user.post_id_in_liked(post_id):
                        like(post, user)
                post.delete()
                self.redirect("/waitredir/1/front")
            else:
                if subject and content:
                    post.subject = subject
                    post.content = content
                    post.put()

                    self.redirect("/" + str(post.key().id()))
                else:
                    error = "Please input both a subject and content."
                    self.render_edit(subject, content, error)
        else:
            self.redirect("/login")


class PostPage(Handler):

    # guests can view the post page so the cookie is collected to see if
    # logged in features are activated.
    def get(self, post_id):
        post = Post.get_by_id(int(post_id))
        u = verify_cookie(self)
        self.render("post.html", post=post, u=u, error="")

    # There are two situations where this handler is posted to: liking a post,
    # and posting a comment.
    def post(self, post_id):
        post = Post.get_by_id(int(post_id))
        u = verify_cookie(self)
        if u:
            if self.request.get("submit_comment"):
                comment = self.request.get("comment")
                author = self.request.get("author")
                if comment and author:
                    post.add_comment(author, comment)
                    self.redirect("/waitredir/1/" + post_id)
                else:
                    self.render("post.html", post=post,
                                u=u,
                                error="Please enter a comment.")
            else:
                if post.author != u.username:
                    like(post, u)
                    self.redirect("/waitredir/1/" + post_id)
                else:
                    self.render("post.html", post=post,
                                u=u,
                                error="You can't like your own"
                                " posts!")
        else:
            self.render("post.html", post=post,
                        u=u,
                        error="You need to be logged in for"
                        " that!")


class LoginHandler(Handler):

    # if the user is logged in they are redirected to the account welcome page,
    # otherwise, they are asked to log in.
    def get(self):
        u = verify_cookie(self)
        if u:
            welcome_redirect(self, u)
        else:
            # serve the login page on GET
            self.render("login.html")

    def post(self):
        # retrieve the username and password and instantiate error
        user_username = str(self.request.get("username"))
        user_pass = str(self.request.get("password"))
        # get the User object with the entered username
        u = user_check(user_username)

        # check to see if the user actually exists
        if u:
            # user exists, now checking the password vs the hash
            hashed = bcrypt.hashpw(user_pass, u.password_hash)
            if u.password_hash == hashed:
                # user is valid, give session cookie and redirect to welcome
                welcome_redirect(self, u)
            else:
                # serve login page with error
                self.render("login.html", error="Invalid login")
        else:
            # serve login page with error
            self.render("login.html", error="Invalid login")


class SignupHandler(Handler):
    # if the user is logged in they are redirected to the account welcome page,
    # otherwise they are asked to sign up.
    def get(self):
        u = verify_cookie(self)
        if u:
            welcome_redirect(self, u)
        else:
            # serve the signup page on GET
            self.render("signup.html")

    # This post handler utilized various helper functions to validate the
    # entered account information. If the information validates successfully,
    # a new User is added to the database and the user is logged in with that
    # info.
    def post(self):
        user_username = str(self.request.get("username"))
        user_pass = str(self.request.get("password"))
        pass_verify = str(self.request.get("verify"))
        user_email = str(self.request.get("email"))

        username = valid_username(user_username)
        password = valid_password(user_pass)
        verify = pass_match(user_pass, pass_verify)
        email = valid_email(user_email)
        if not user_check(user_username):
            username_check = True
        else:
            username_check = False

        username_error = ""
        password_error = ""
        verify_error = ""
        email_error = ""

        if not (username and password and verify and email and username_check):
            if not username:
                username_error = "That's not a valid username."
            elif not username_check:
                username_error = "That user already exists."
            if not password:
                password_error = "That wasn't a valid password."
            elif not verify:
                verify_error = "Your passwords didn't match."
            if not email:
                email_error = "That's not a valid email."
            self.render("signup.html", username=user_username,
                        username_error=username_error,
                        password_error=password_error,
                        verify_error=verify_error,
                        email=user_email,
                        email_error=email_error)
        else:
            # hash the user password with bcrypt
            hashed = bcrypt.hashpw(user_pass, bcrypt.gensalt())
            # make a new user object and insert it into the user database
            u = User(username=user_username,
                     password_hash=hashed,
                     email=user_email)
            u.put()
            # generate and set the session cookie
            welcome_redirect(self, u)


# serves the welcome page, if user is not logged in they are redirected to
# login.
class WelcomeHandler(Handler):

    def get(self):
        u = verify_cookie(self)
        if u:
            self.render("welcome.html", username=u.username)
        else:
            self.redirect("/login")


# clears the session cookie and redirects to login.
class LogoutHandler(Handler):

    def get(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')
        self.redirect("/login")


# serves a page that makes the user wait for a second before redirecting to
# their intended destination. This allows the server to update completely
# after any user changes, preventing any ghost data.
class WaitRedirect(Handler):

    def get(self, time, tgt):
        if "front" in tgt:
            tgt = '/'
        else:
            tgt = '/' + tgt
        self.render("waitredir.html", time=time, tgt=tgt)

# registering all of the routes.
app = webapp2.WSGIApplication([
    ('/', MainPage),
    ('/newpost', SubmitPage),
    ('/(\d+)', PostPage),
    ("/signup", SignupHandler),
    ("/welcome", WelcomeHandler),
    ("/login", LoginHandler),
    ("/logout", LogoutHandler),
    ("/edit/(\d+)", EditPage),
    ("/(\d+)/([a-f0-9]{32})", EditComment),
    ("/waitredir/(\d+)/(\w+|\d+)", WaitRedirect)
], debug=True)

# Helper functions

# regex functions
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


def user_check(username):
    # query for the username
    user_chk = User.gql("WHERE username = :1", username).get()
    # if the username exists, return it's User object
    return user_chk


# a function that creates the session cookie and redirects to the welcome page
# after a successful login.
def welcome_redirect(s, u):
    user_id = str(u.key().id())
    user_id_hash = hmac.new(secret.secret(), user_id).hexdigest()
    user_id_cookie = "%s|%s" % (user_id, user_id_hash)

    s.response.headers.add_header('Set-Cookie',
                                  'user_id=%s; Path=/' % user_id_cookie)

    s.redirect("/welcome")


# a function that verifies the user's sessing cookie and return's the user's
# database object on success.
def verify_cookie(s):
    if ('user_id' in s.request.cookies) and \
       s.request.cookies.get('user_id') != '':
        # unpack the cookie
        cookie = s.request.cookies.get('user_id').split('|')
        user_id = cookie[0]
        cookie_hash = cookie[1]
        # verify the cookie
        user_id_hash = hmac.new(secret.secret(), user_id).hexdigest()
        if cookie_hash == user_id_hash:
            # get the valid user's username and return the User object
            try:
                username = User.get_by_id(int(user_id)).username
            except AttributeError:
                return None
            return user_check(username)
        else:
            # return None on bad cookie
            return None
    else:
        # cookie doesn't exist, return None
        return None


# a function to handle the changes in the User and Post objects when a post
# is liked.
def like(p, u):
    p_id = p.key().id()
    if not u.liked:
        p.likes += 1
        u.liked = ',' + str(p_id)
    elif not (u.post_id_in_liked(p_id)):
        p.likes += 1
        u.liked += ',' + str(p_id)
    else:
        p.likes -= 1
        u.liked = u.liked.replace(',' + str(p_id), '')
    p.put()
    u.put()
