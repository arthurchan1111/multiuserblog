import webapp2
import os
import jinja2
import random
import string
import hashlib
import hmac
import bcrypt
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja = jinja2.Environment (loader = jinja2.FileSystemLoader(template_dir),
autoescape = True)

def render_str(self, template, **params):
    gettemp = jinja.get_template(template)
    return gettemp.render(params)

def pw_hash(pw):
    salt= bcrypt.gensalt()
    h = bcrypt.hashpw(pw,salt)
    return '%s,%s' % (h,salt)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        return render_str(template, **params)

    def render(self, template, **kw):
        self.write(self.render_str(template,**kw))

    def set_secure_cookie(self, name, val):
        cookie_val = make_secure_val(val)
        self.response.headers.add_header(
            'Set-Cookie',
            '%s=%s; Path=/' % (name, cookie_val))

    def read_secure_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and check_secure_val(cookie_val)

    def login(self, user):
        self.set_secure_cookie('user_id', str(user.key().id()))

    def logout(self):
        self.response.headers.add_header('Set-Cookie', 'user_id=; Path=/')

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_secure_cookie('user_id')
        self.user = uid and User.by_id(int(uid))


def blog_key(name='default'):
    return db.Key.from_path('blogs',name)

def render_post(response, post):
    response.out.write('<b>' + post.subject + '</b><br>')
    response.out.write(post.content)

class Logout(BHandler):
    def get(self):
        self.logout()
        self.redirect('/login')

class Post(db.Model):
    subject = db.StringProperty(required= True)
    content = db.TextProperty(required = True)
    created = db.DateTimeProperty(auto_now_add= True)
    last_modified= db.DateTimeProperty(auto_now = True)

    def render(self):
        self.render_txt=self.content.replace('\n' '<br>')
        return render_str("post.html", p=self)

def users_key(group = 'default'):
    return db.Key.from_path('users', group)

class User(db.Model):
    username= db.StringProperty(required = True)
    password_hash= db.StringProperty(required= True)
    email = db.StringProperty(required= True)
    salt = db.StringProperty()
    @classmethod
    def by_id(cls, id):
        return cls.get_by_id(uid, parent = )

    @classmethod
    def namelookup(cls, name):
        uname = db.GqlQuery("SELECT * FROM USER"
                            "WHERE username="name)
        return uname
    @classmethod
    def register(cls, name, pw, email):
        hashed_pw= pw_hash(pw)
        pw_list=hashed_pw.split(",")
        return User(parent=users_key(),
                    name= name
                    password_hash=pw_list[0]
                    email= email
                    salt =pw_list[1])
    @classmethod
    def ulogin(cls, name, pw):
        user=cls.by_name(name)
        if user and valid_pw(name, pw, u.pw_hash):
        return user

class PostPage(Handler):
    def get(self, post_id):
        key = db.Key.from_path('Post', int(post_id), parent=blog_key())
        post = db.get(key)

        if not post:
            self.error(404)
            return

        self.render("permalink.html", post=post)

class MainPage(Handler):
    def get(self):
        posts=db.GqlQuery("SELECT * FROM POST"
                        "ORDER BY last_modified limit 10")
        self.render("index.html" posts = posts, username=username)

class NewPost(Handler):
    def get(self):
        self.render("newpost.html")

    def post(self):
        subject = self.request.get('subject')
        content = self.request.get('content')

        if subject and content:
            p = Post(blog_key(), subject= subject, content=content)
            p.put()
            self.redirect('/blog/%s' % str(p.key().id()))

        else:
            error = "Missing subject or content"
            self.render("newpost.html", subject=subject, content=content, error=error)

class LoginPage(Handler):
    def get(self):
        self.render("login.html")

    def post(self):
        username= self.request.get('username')
        password= self.request.get('password')

        login = User.login(username, password)
        if login:
            self.login(login)
            self.redirect('/')

app = webapp2.WSGIApplication([
    ('/', MainPage),
], debug=True)
