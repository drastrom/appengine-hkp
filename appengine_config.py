from google.appengine.ext import vendor
import os

# Add any libraries installed in the "lib" folder.
vendor.add(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lib'))
# Add python-pgpdump git submodule
vendor.add(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lib', 'python-pgpdump'))
# Add py2casefold git submodule
vendor.add(os.path.join(os.path.dirname(os.path.realpath(__file__)), 'lib', 'py2casefold'))

def webapp_add_wsgi_middleware(app):
	from google.appengine.ext.appstats import recording
	app = recording.appstats_wsgi_middleware(app)
	return app

