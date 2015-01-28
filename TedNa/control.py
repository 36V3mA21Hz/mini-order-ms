import webapp2
import os
import jinja2
from google.appengine.ext import db

template_dir = os.path.join(os.path.dirname(__file__), 'templates')
jinja_env = jinja2.Environment(loader = jinja2.FileSystemLoader(template_dir), autoescape=True)

class Handler(webapp2.RequestHandler):
    def write(self, *a, **kw):
        self.response.out.write(*a, **kw)

    def render_str(self, template, **params):
        t = jinja_env.get_template(template)
        return t.render(params)

    def render(self, template, **kw):
        self.write(self.render_str(template, **kw))

class BlogEntries(db.Model):
    subject = db.StringProperty(required = True)
    content = db.TextProperty(required=True)
    created=db.DateTimeProperty(auto_now_add=True)

class MainPage(Handler):
    def render_home(self, subject="", content="", error=""):
        blogEntries = db.GqlQuery("SELECT * FROM BlogEntries \
                                    ORDER BY created DESC")
        self.render("home.html", subject=subject, content=content, error=error, blogEntries=blogEntries)

    def get(self):
        self.render_home()

class NewPostPage(Handler):
    def render_front(self, subject="", content="", error=""):
        blogEntries = db.GqlQuery("SELECT * FROM BlogEntries \
                                    ORDER BY created DESC")
        self.render("m1.html", subject=subject, content=content, error=error, blogEntries=blogEntries)

    def get(self):
        self.render_front()

    def post(self):
        subject = self.request.get("subject")
        content = self.request.get("content")
        if subject and content:
            a = BlogEntries(subject=subject, content=content)
            a.put()
            blog_id = a.key().id()
            self.redirect("/%s" % blog_id)
        else:
            error = "we need both a subject and some blog content!"
            self.render_front(error=error)

class BlogEntryPage(Handler):
    def render_blog(self, blog_id, error=""):
        blogEntry = BlogEntries.get_by_id(long(blog_id))
        #self.response.out.write(blogEntry.content)             
        self.render("blogEntry.html", error=error, blogEntry=blogEntry)

    def get(self, blog_id):
        self.render_blog(blog_id)

app = webapp2.WSGIApplication([('/', MainPage), ('/newpost', NewPostPage),
        (r'/(\d+)', BlogEntryPage)], debug=True)
