from app import app, encoder, mailTrigger, helper
import logging
from flask import request, jsonify
from email_validator import validate_email, EmailNotValidError
import json
import time
import base64
import boto3
logging.basicConfig(level=logging.DEBUG)
# Get the service resource.
# dynamodb = boto3.client(
#     'dynamodb',
#     # Hard coded strings as credentials, not recommended.
# #    aws_access_key_id='AKIAIO5FODNN7EXAMPLE',
#  #   aws_secret_access_key='ABCDEF+c2L7yXeGvUyrPgYsDnWRRC1AYEXAMPLE'
#     aws_access_key_id='ASIAWGE77G4XFQ7GPQOH',
#     aws_secret_access_key='88JeiPPA3+NTMoDgBA601iG21nxDZ0+aleHEuftR',
#     aws_session_token='FwoGZXIvYXdzENP//////////wEaDKzMnZU3HzJp30XWaiK+AayWXCw/Pdn7gu64TAM7VVaRdBkyqehAwajSpXErol23Qke+LzUZ2fPlWzuSwwf/SFbRo20FI0tbqRJ5qIaHSPnzdF/9abE/WJBJ1EOpAVBiWQplboYn4ITSESnlTfKMou20l/+lpNZPc6XUHfjcqJFYgRnibbsGCK7Y7wpPv14nLHIw4SEehI9R8k9Gcty1L6pPrDXVrWrPz9Uxmnh5xw8GC9tE5ZoMzXW5JBYeHfCDQyA6qWFXfvmkBjZhFc8o24GM8wUyLSyncH/i0h0MnZth+I2mw+IA5On7Ni6Zc1GCG4d7YW+0fi0jpvHVQo3gXZtVnw=='
# )
session = boto3.Session(
aws_access_key_id='ASIA2XMYS43NTTZPQ6JT',
aws_secret_access_key='nCea45sH6z/O0FVkf+XJu1kOTz7W/r1/oqB55abD',
aws_session_token='FwoGZXIvYXdzEMb//////////wEaDCKQMPpXHja6DsfFHSK+AVZkpdp0d3PJ1dXUoh+Dp5YZgrbvNJewzS5lGH78ggxT15Rp+9247QAj0qZ8G4NclErrHsQBIyLrwKXxT0Y4ZwskKxOcUWv2zIQ9el2MXjZmUb9OYBJLIeQ3p//uGJdnZoN98UZaH5S0/cYZECeUSW+SjJh4VGrYbA68uegJzaq+9s5KKKDJfButPoETC+C3TRZEG8fDKWyen/4gW4M9FZGEIFqtworAMM2BV1QT1PeqSo19P4q6/ODAzVF80Vco4J7B8wUyLQ4An8ekB8MQCQwJqySx3Nhr82rHl2lvItJKNTlEQEFfXSb2P7PtDccdFEXr2g=='
)
dynamodb = session.resource('dynamodb')
# dynamodb = boto3.resource('dynamodb')

# Instantiate a table resource object without actually
# creating a DynamoDB table. Note that the attributes of this table
# are lazy-loaded: a request is not made nor are the attribute
# values populated until the attributes
# on the table resource are accessed or its load() method is called.
table = dynamodb.Table('User')

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
        data = request.get_json()
        ##
        email = data.get("email")
        password = data.get("password")
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
