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
aws_access_key_id='ASIAVBLO43SBNDWK3IFY',
aws_secret_access_key='FTirvlKR7chchm7VhEKpwKcpVZO7UMdsaHkFb4xe',
aws_session_token='FwoGZXIvYXdzEAwaDHPC1BXZvD7joKzDOyK+AXqHeKp7bAqaTYcOFBi6MVrzjrOpdcvaKu+ygMSHFVYbTCO/7QcBnC50usSeBehDRktNXR5bbx6sWB/kaTju4GOJlGl2MyLXqrGU5mgAVRxn7O+G1nrX3G2JKR2dTsxOHM7xxCTOIkiYZ9kvGkV/B0DkJ/cviV+pT7PlCTQKcD2MKKyGe/xhtLgSbAvVGzv3DYYf44h8VQr8FetdkRTcfBjKTDcW8kxpF1q4EDPeZLhiGbxWfG1iwD+I8cxkMxoo2PiI9AUyLf/NBzJYjzq7SG7C0lLDrH8suv0oVYAANKtu7VdmqIGoKfW+ELRgil7/RhMXoA==',
region_name='us-east-1')
dynamodb = session.resource ('dynamodb')
# dynamodb = boto3.resource('dynamodb')
table = dynamodb.Table('User')
@app.route("/")
def hello():
    return "Home page"
def getDataFromRequest(dataObj,keyValue,requestObj=None):
    if dataObj is not None:
        return base64.b64decode(dataObj.get(keyValue)).decode("ascii")
    else:
        return base64.b64decode(request.args.get(keyValue)).decode("ascii")

@app.route('/user' , methods=['POST'])
def check_logged_in_status():
    response_json = {}
    response_json["message"] = "error"
    try:
        data = request.get_json()
        ##
        email = getDataFromRequest(dataObj=data,keyValue="email")
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

        app.logger.debug("Test")
        userName = getDataFromRequest(dataObj=data,keyValue="name")
        email = getDataFromRequest(dataObj=data,keyValue="email")
        password = getDataFromRequest(dataObj=data,keyValue="password")
        ##
        password = helper.encryptValue(password)
        # print(email)
        app.logger.debug(email)
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
        email = getDataFromRequest(dataObj=data,keyValue="email")
        otp = getDataFromRequest(dataObj=data,keyValue="OTP")
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
        email = getDataFromRequest(dataObj=None,keyValue="email",requestObj=request)
        password = getDataFromRequest(dataObj=None,keyValue="password",requestObj=request)
        # fetch data from db and verify the email, password values
        app.logger.debug("hhhhh")
        app.logger.debug(email)
        app.logger.debug(password)
        response = table.get_item(
            Key={
                'EMAIL_ID': email
            }
        )
        if 'Item' in response:
            item = response['Item']
            orgPass = item['PASSWORD'].value
            if password == helper.decryptValue(orgPass):
                app.logger.debug("Check passed")
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
