from app import app, encoder, mailTrigger, helper
import logging
from flask import request, jsonify
from email_validator import validate_email, EmailNotValidError
import json
import time
import base64
import boto3
logging.basicConfig(level=logging.DEBUG)
session = boto3.Session(
aws_access_key_id='ASIAWGE77G4XBNJUFIMM',
aws_secret_access_key='5efszffVaCa3NPFWEw3mgjFCUnEC9MVK/oMgvvoW',
aws_session_token='FwoGZXIvYXdzEAoaDIdk6y4ck+tRbJOSFSK+AbYmPmTzHRiNq57wLtFQbELEYmZQwxBnsQDKVex+PL6filjxL40i0PEhjJCJLAtZUWmEIgNEDWkUmVoQr2TdETDR46lQ8cau2UWv0e1NTc57VrueZKOGEVorqY92J2TwbYTaTr/UDwEbNq75hPyE6Qby8+i4p+pdJ8Rv8n+7yDmBchHRnzTrTMhfcRQsNz2lJOx7sIwBMgGhk+RQiwNoz1LR2qpuq6lfKBAur4iHhYKxlbzsAWcVgnxERp2TjA8og5vQ8wUyLfZzuhOxwX4tjcvdCXRt3PBqjXBH2FG+aRr7PAaW1AjxQC0eNJtu/9lpI5a3rA==',
region_name='us-east-1'
)
dynamodb = session.resource ('dynamodb')
# dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('User')
'''
@app.route("/")
def hello():
    return "Home page"
'''
@app.route('/user' , methods=['POST'])
def check_logged_in_status():
    response_json = {}
    response_json["message"] = "error"
    try:
        data = request.get_json()
        ##
        email = data.get("email")
        if encoder.check_validity_token(request.headers['token'],email):
            response_json["message"] = "ok"
    except Exception as e:
        app.logger.debug(e)
    return json.dumps(response_json)

@app.route('/user/create' , methods=['POST'])
def create_new_user():
    response_json = {}
    response_json["message"] = "error"
    try:
        ##
        data = request.get_json()
        ##
        userName = data.get("name")
        email = data.get("email")
        password = data.get("password")
        validate_email(email)
        ##

        # Print out some data about the table.
        # This will cause a request to be made to DynamoDB and its attribute
        # values will be set based on the response.
        app.logger.debug(table.creation_date_time)
        ##
        sentOTP = helper.sendOTPMail(email)
        # insert values into the database , along with time and otp and return message
        table.put_item(
            Item={
                'USER_NAME': userName,
                'EMAIL_ID': email,
                'PASSWORD': password,
                'OTP' : sentOTP,
                'OTP_GEN_TIME': int(round(time.time() * 1000))
            }
        )
        #trigger email to the user mail
        response_json["message"] = "ok"
    except EmailNotValidError as emailError:
        app.logger.debug("email id given is wrong - " + str(emailError))
        response_json["error"] = "email id given is either not reachable or invalid"
    except Exception as e:
        app.logger.debug(e)
    #
    return json.dumps(response_json)

@app.route('/user/verify', methods=['POST'])
def verifyOTP():
    response_json = {}
    response_json["message"] = "error"
    try:
        ##
        data = request.get_json()
        ##
        email = data.get("email")
        otp = data.get("OTP")
        submittedTime = int(round(time.time() * 1000))
        # fetch data from db and verify the OTP values
        response = table.get_item(
            Key={
                'EMAIL_ID': email
            }
        )
        if 'Item' in response:
            item = response['Item']
            ##
            genOTP = item['OTP']
            genTime = item['OTP_GEN_TIME']
            if genOTP == otp and ( ( submittedTime - genTime ) <= 1800000 ):
                response_json["message"] = "ok"
                response_json["token"] = encoder.encode_auth_token(email).decode('utf-8')
            app.logger.debug(submittedTime - genTime)
            # response_json["message"] = "ok"
            # response_json["token"] = encoder.encode_auth_token(email).decode('utf-8')
        ##
    except Exception as e:
        app.logger.debug(e)
    #
    return json.dumps(response_json)

@app.route('/user/login')
def verifyLogin():
    response_json = {}
    response_json["message"] = "error"
    try:
        # data = request.get_json()
        ##
        app.logger.debug(request)
        email = request.args.get("email")
        password = request.args.get("password")
        # fetch data from db and verify the email, password values
        response = table.get_item(
            Key={
                'EMAIL_ID': email
            }
        )
        if 'Item' in response:
            item = response['Item']
            orgPass = item['PASSWORD']
            if password == orgPass:
                genOTP = helper.sendOTPMail(email)
                # update the generated OTP
                table.update_item(
                    Key={
                        'EMAIL_ID': email
                    },
                    UpdateExpression='SET OTP = :val1 , OTP_GEN_TIME = :val2',
                    ExpressionAttributeValues={
                        ':val1': genOTP,
                        ':val2' : int(round(time.time() * 1000))
                    }
                )
                response_json["message"] = "ok"
        ##
    except Exception as e:
        app.logger.debug(e)
    #
    return json.dumps(response_json)
