from provider import MyProvider
from validator import MyRequestValidator

oauth = MyProvider()
oauth._validator = MyRequestValidator()
