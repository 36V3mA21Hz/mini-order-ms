import webapp2
import os
import jinja2
import re
import sys
import hashlib
import string
import random
import urllib2
import json
import logging
import time

from datetime import datetime
from xml.dom import minidom
from string import letters
from google.appengine.ext import db
from google.appengine.api import memcache

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

def render_str(template, **params):
    t = jinja_env.get_template(template)
    return t.render(params)

class RenderPage:
    @classmethod
    def render_table_header(cls):
        return render_str("tableHeader.html")


### Main Handler ###
class MainHandler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        params['user'] = self.user
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

    def set_cookie(self, name, val):
        cookie_val = Accounts.make_hash_val(val)
        self.response.headers.add_header('Set-Cookie', '%s=%s;Path=/' % (name, cookie_val))

    def read_cookie(self, name):
        cookie_val = self.request.cookies.get(name)
        return cookie_val and Accounts.check_hash_val(cookie_val)

    def login_set_cookie(self, user):
        self.set_cookie('user_id', str(user.key().id()))

    def initialize(self, *a, **kw):
        webapp2.RequestHandler.initialize(self, *a, **kw)
        uid = self.read_cookie('user_id')
        self.user = uid and User.query_by_id(int(uid))

### Accounts System ###
class Accounts:
    USER_RE = re.compile(r"^[a-zA-Z0-9_-]{3,20}$")
    @classmethod
    def valid_username(cls, username):
	 return cls.USER_RE.match(username)

    PASS_RE = re.compile(r"^.{3,20}$")
    @classmethod
    def valid_password(cls, password):
	 return cls.PASS_RE.match(password)

    EMAIL_RE = re.compile(r"^[\S]+@[\S]+\.[\S]+$")
    @classmethod
    def valid_email(cls, email):
	 return cls.EMAIL_RE.match(email)

    COOKIE_RE = re.compile(r'.+=;\s*Path=/')
    @classmethod
    def valid_cookie(cls, cookie):
	return cookie and cls.COOKIE_RE.match(cookie)

    @classmethod
    def make_hash_val(cls, name):
	h = hashlib.sha256(name).hexdigest()
	return "%s|%s" %(name, h)

    @classmethod
    def check_hash_val(cls, hashed_val):
	x = hashed_val.split('|')[0]
	if  hashed_val == Accounts.make_hash_val(x):
            return x

    @classmethod
    def make_salt(cls):
	return ''.join([random.choice(string.letters) for x in xrange(5)])

    @classmethod
    def make_password(cls, name, pw, salt=None):
	if not salt:
	    salt = cls.make_salt()
	h = hashlib.sha256(name + pw + salt).hexdigest()
	return "%s|%s" %(h, salt)

    @classmethod
    def valid_pw(cls, name, pw, h):
	salt = h.split('|')[1]
	return h == Accounts.make_password(name, pw, salt)

class SignupPage(MainHandler):

    def get(self):
        self.render("signup.html")

    def post(self):

        has_fault = False
        username = self.request.get("username")
        password = self.request.get("password")
        verify = self.request.get("verify")
        email = self.request.get("email")

        u = User.query_by_name(username)
        if u:
            self.render('signup.html', error_username="User already exists.")
            return
 
        params = dict(username = username, email = email)

        if not Accounts.valid_username(username):
            params['error_username'] = "Invalid Username"
            has_fault = True

        if not Accounts.valid_password(password):
            params['error_password'] = "Invalid Password"
            has_fault = True
        elif verify != password:
            params['error_verify'] = "Passwords Mismatch"
            has_fault = True

        if email and not Accounts.valid_email(email):
            params['error_email'] = "Invalid email"
            has_fault = True

        if has_fault:
            self.render("signup.html", **params)
        else:
            u = User.registerUser(username, password, email)
            u.put()

            self.login_set_cookie(u)
            self.redirect('/')

class LoginPage(MainHandler):
    def get(self):
        self.render("login.html")

    def post(self):
        username = self.request.get("username")
        password = self.request.get("password")
        valid_login = False

        u = User.getUser(username, password)

        if not u:
            self.render("login.html", error_message="Invalid Login") 
        else:
            self.login_set_cookie(u)
            self.redirect('/')
            

class LogoutPage(MainHandler):
    def get(self):
        self.set_cookie("user_id", "")
        self.redirect('/')

### User ###
class User(db.Model):
    name = db.StringProperty(required = True)
    pw_hash = db.StringProperty(required = True)
    email = db.StringProperty()

    @classmethod
    def users_key(cls, group = 'default'):
        return db.Key.from_path('users', group)


    @classmethod
    def query_by_name(cls, name):
        u = User.all().filter('name =', name).get()
        return u

    @classmethod
    def query_by_id(cls, uid):
        return User.get_by_id(uid, parent = User.users_key())
        
    
    @classmethod
    def getUser(cls, name, pw):
        u = cls.query_by_name(name) 
        if u and Accounts.valid_pw(name, pw, u.pw_hash):
            return u
    @classmethod
    def registerUser(cls, name, pw, email= None):
        return User(parent= User.users_key(), name=name, pw_hash=Accounts.make_password(name, pw), email=email)

### Cache ###
class Cache:
    @classmethod
    def top_wikis(cls, update = False):
	k1 = 'top'
	wikis = memcache.get(k1)
	t = memcache.get(k2)
	if wikis is None or update:
		t = datetime.now()
		wikis = db.GqlQuery("SELECT * "
					"FROM ShoppingItems "
					"WHERE ANCESTOR IS :1 "
					"ORDER BY created DESC "
					"LIMIT 10",
					ShoppingItems.wiki_key())
		wikis = list(wikis)
		#logging.error("The len is %s", len(wikis))
		memcache.set(k1, wikis)
	return wikis, t


### Wiki Pages ###
class OrderItems(db.Model):
    item_name       = db.StringProperty(required = True)
    order_time      = db.DateTimeProperty(required = True)
    selling_price   = db.FloatProperty(required = False)
    item_quantity   = db.IntegerProperty(required = False)
    price_usd       = db.FloatProperty(required = True)
    price_rmb       = db.FloatProperty(required = False)
    forex           = db.FloatProperty(required = False)
    shipped         = db.BooleanProperty(required = True)
    mark            = db.TextProperty(required = False)
    link            = db.LinkProperty(required = False)
    
    @classmethod
    def order_items_key(cls, name = 'default'):
	return db.Key.from_path('order_items', name)

    def render_item(self):
        return render_str("singleItem.html", shopping_item = self)
   
    def render_after_update(self):
        return render_str("queryOne.html", shopping_item = self, rp=RenderPage)


class HomePage(MainHandler):
    def render_home(self):
        self.render("home.html")

    def get(self):
	self.render_home()

class ListItemsPage(MainHandler):
    def get(self):
        if not self.user:
            self.redirect("/login")
            return
        shopping_items = db.GqlQuery("SELECT * "
                            "FROM OrderItems "
                                "WHERE ANCESTOR IS :1 "
                                "ORDER BY order_time DESC "
                                "LIMIT 100",
                                OrderItems.order_items_key())
        shopping_items = list(shopping_items)
        self.render("queryAll.html", shopping_items=shopping_items, rp = RenderPage)

def ftos(x):
    return float(x) if '.' in x else float(int(x))
    
class UpdateItemsPage(MainHandler):
    def render_update(self, **params):
        self.render("updateItems.html",  **params)

    def get(self):
        if self.user:
            self.render_update()
        else:
            self.redirect("/login")

    def post(self):
        
        item_name       =  self.request.get("item_name")
        order_time      =  self.request.get("order_time")
        selling_price   =  self.request.get("selling_price")
        item_quantity   =  self.request.get("item_quantity")
        price_usd       =  self.request.get("price_usd")
        price_rmb       =  self.request.get("price_rmb")
        forex           =  self.request.get("forex")
        shipped         =  self.request.get("shipped")
        mark            =  self.request.get("mark")
        link            =  self.request.get("link")

        items_params = {}

        items_params['item_name'] = item_name    
        items_params['order_time'] = order_time
        items_params['selling_price'] = selling_price
        items_params['item_quantity'] = item_quantity
        items_params['price_usd'] = price_usd
        items_params['price_rmb'] = price_rmb
        items_params['forex'] = forex
        items_params['shipped'] = shipped     
        items_params['link'] = link         
        items_params['mark'] = mark         

        has_fault = False
        if not order_time:
            items_params['error_order_time'] = "Empty"
            has_fault = True
        else:
            try:
                order_time = datetime.strptime(order_time, '%m/%d/%Y')  
            except ValueError:
                items_params['error_order_time'] = "Wrong Format"
                has_fault = True
            else:
                items_params['order_time'] = order_time

        if not item_name:
            items_params['error_item_name'] = "Please type in name"
            has_fault = True
            
        if not selling_price:
            del(items_params['selling_price'])
        else:
            try:
                items_params['selling_price'] = ftos(selling_price)
            except ValueError:
                items_params['error_selling_price'] = "Wrong Format"
                has_fault = True

        if not item_quantity:
            del(items_params['item_quantity'])
        else:
            try:
                items_params['item_quantity'] = int(item_quantity)
            except ValueError:
                items_params['error_item_quantity'] = "Wrong Format"
                has_fault = True
            
        if not price_usd:
            items_params['error_price_usd'] = "Empty"
            has_fault = True
        else:
            try:
                items_params['price_usd'] = ftos(price_usd)
            except ValueError:
                items_params['error_price_usd'] = "Wrong Format"
                has_fault = True
            
        if not price_rmb:
            del(items_params['price_rmb'])
        else:
            try:
                items_params['price_rmb'] = ftos(price_rmb)
            except ValueError:
                items_params['error_price_rmb'] = "Wrong Format"
                has_fault = True

        if not forex:
            del(items_params['forex'])
        else:
            try:
                items_params['forex'] = ftos(price_usd)
            except ValueError:
                items_params['error_forex'] = "Wrong Format"
                has_fault = True

        logging.error("%s", shipped)
        items_params['shipped']  = True if shipped == "Yes" else False     
        logging.error("%s", items_params['shipped'])

        items_params['mark'] = mark         

        if link:
            items_params['link'] = link         
        else:
            del(items_params['link'])
       
        if not has_fault:
            items_params['parent'] = OrderItems.order_items_key()
            a = OrderItems(**items_params) 
            a.put()
            items_params['shopping_item'] = a
            self.render_update(**items_params)
        else:
            self.render_update(**items_params)

app = webapp2.WSGIApplication([('/', HomePage), 
                                ('/updateItems', UpdateItemsPage),
                                ('/listItems', ListItemsPage),
                                ('/login', LoginPage),
                                ('/signup', SignupPage),
                                ('/logout', LogoutPage)
                            ],
                             debug=True)

