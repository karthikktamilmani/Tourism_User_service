from testRun import app
from flask import json
import os
import unittest
import base64


class BasicTests(unittest.TestCase):
    def setUp(self):
        self.app = app.test_client()
        self.app.testing = True
        pass

    def test_createUserInvalidEmail(self):

        #encoding input
        # nameString = "test".encode('ascii')
        # name = base64.b64encode(nameString)
        # emailString = "blaabla".encode('ascii')
        # email = base64.b64encode(emailString)
        # passwordString = "pass".encode('ascii')
        # password = base64.b64encode(passwordString)

        # name = base64.b64encode( bytes("test", "utf-8") )
        # email = base64.b64encode( bytes("blabla", "utf-8") )
        # password = base64.b64encode( bytes("pass", "utf-8") )
        #sending the request
        response = self.app.post('/user/create',
        json={'name': 'dGVzdAo=', 'email': 'YmxhYmxhYmxh', 'password': 'aGVsbG8='},
        content_type='application/json',)

        data = json.loads(response.get_data(as_text=True))
        assert data['message'] == 'error'
        assert data['error'] == 'email id given is either not reachable or invalid'






if __name__ == "__main__":
    unittest.main()
