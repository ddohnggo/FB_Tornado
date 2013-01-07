import tornado.web
import tornado.options
import tornado.httpserver
import tornado.ioloop
import tornado.auth
import tornado.autoreload

import os
import logging
import pymongo 
import json

from tornado.options import options, define

define("port", default=8000, type=int)
define("facebook_api_key")
define("facebook_secret")
define("cookie_secret")
define("mongo_host")
define("mongo_db", type=int)
define("scope")

class MainHandler(tornado.web.RequestHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        self.write("hi")
	access_token = self.get_secure_cookie("access_token")

	if not access_token:
	    self.redirect('/auth/login')
	    return

	self.facebook_request(
	    "/me/photos",
	    access_token=access_token,
	    callback=self.async_callback(self._on_load))
	    
    def _on_load(self, response):
        if not response['data']:
	    self.redirect('/auth/login')

	for i in response['data']:
	    print json.dumps(i, indent=4)

	self.write(response)

class LoginHandler(tornado.web.RequestHandler, tornado.auth.FacebookGraphMixin):
    @tornado.web.asynchronous
    def get(self):
        self.write("no")
	user_id = self.get_secure_cookie("user_id")

        # if the access token exists get the user
	if self.get_argument("code", None):
	    print self.get_argument("code")
            self.get_authenticated_user(
                redirect_uri='http://localhost:8000/auth/login',
		client_id=options.facebook_api_key,
		client_secret=options.facebook_secret,
		code=self.get_argument("code"),
		callback=self.async_callback(
		    self._on_login))
	    return
	# check to see whether we've logged this user in a cookie
	elif self.get_secure_cookie("access_token"):
	    self.redirect('/')
	    return
 
        # redirect to fb app auth dialog returns auth token
	self.authorize_redirect(
	    redirect_uri='http://localhost:8000/auth/login',
	    client_id = self.settings["facebook_api_key"],
	    extra_params = {"scope": options.scope}
	)

    def _on_login(self, user):
        if not user:
	    self.clear_all_cookies()
	    raise tornado.web.HTTPError(500, "Facebook authentication failed")

	print user
  
        # write to the cookie
	self.set_secure_cookie('user_id', str(user['id']))
	self.set_secure_cookie('name', str(user['name']))
        self.set_secure_cookie('fbid', str(user['id']))
	self.set_secure_cookie('locale', str(user['locale']))
	self.set_secure_cookie('access_token', str(user['access_token']))
	self.set_secure_cookie('session_expires', str(user['session_expires']))

	# write to mongo db
	user_db = self.application.db.users
	user = {
	    "user_id": str(user['id']), 
	    "name": str(user['name']),
	    "fbid": str(user['id']),
	    "locale": str(user['locale']),
	    "access_token": str(user['access_token'])
	    }
        user_db.save(user)
	self.redirect('/')

class Application(tornado.web.Application):
    def __init__(self):
        dir_name = os.path.dirname(__file__)
	conn = pymongo.Connection(options.mongo_host, options.mongo_db)
	self.db = conn['app']
        handlers = [
            (r'/', MainHandler),
	    (r'/auth/login', LoginHandler)
        ]
        settings = {
            "template_path": os.path.join(dir_name, "templates"),
	    "static_path": os.path.join(dir_name, "static"),
	    "facebook_api_key": options.facebook_api_key,
	    "facebook_secret": options.facebook_secret,
	    "cookie_secret": options.cookie_secret,
	    "xsrf_cookies": True
        }
        super(Application, self).__init__(handlers, **settings)

def main():
    tornado.options.parse_command_line()
    dir_name = os.path.dirname(__file__)
    path = os.path.join(dir_name, "settings_dev.py")
    tornado.options.parse_config_file(path)
    tornado.autoreload.add_reload_hook(lambda: "x")
    tornado.autoreload.start()
    http_server = tornado.httpserver.HTTPServer(Application())
    http_server.listen(options.port)
    tornado.ioloop.IOLoop.instance().start()

if __name__ == '__main__':
    main()
