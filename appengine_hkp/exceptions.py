#!/usr/bin/env python

class HttpStatusException(Exception):
	def __init__(self, code, msg):
		self.code = code
		self.msg = msg
		self.status_line = '{} {}'.format(self.code, self.msg)
		super(HttpStatusException, self).__init__(self.status_line)

class HttpNotFoundException(HttpStatusException):
	def __init__(self):
		super(HttpNotFoundException, self).__init__(404, 'Not Found')

class HttpNotImplementedException(HttpStatusException):
	def __init__(self):
		super(HttpNotImplementedException, self).__init__(501, 'Not Implemented')

class HttpBadRequestException(HttpStatusException):
	def __init__(self):
		super(HttpBadRequestException, self).__init__(400, 'Bad Request')

class HttpForbiddenException(HttpStatusException):
	def __init__(self):
		super(HttpForbiddenException, self).__init__(403, 'Forbidden')

class HttpTeapotException(HttpStatusException):
	def __init__(self):
		super(HttpTeapotException, self).__init__(418, 'I\'m a teapot')

