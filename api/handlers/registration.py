from json import dumps
from logging import info
from tornado.escape import json_decode, utf8
from tornado.gen import coroutine
from os import environ
from os import urandom
from ..crypto import encrypt_aes_256, hash_password
from .base import BaseHandler

class RegistrationHandler(BaseHandler):

    @coroutine
    def post(self):
        try:
            body = json_decode(self.request.body)
            email = body['email'].lower().strip()
            if not isinstance(email, str):
                raise Exception()
            phone = body['phone']
            if not isinstance(phone, str):
                raise Exception()
            address = body['address']
            if not isinstance(address, str):
                raise Exception()
            dateofbirth = body['dateofbirth']
            if not isinstance(dateofbirth, str):
                raise Exception()
            disabilities = body['disabilities']
            if not isinstance(disabilities, str):
                raise Exception()
            password = body['password']
            if not isinstance(password, str):
                raise Exception()
            display_name = body.get('displayName')
            if display_name is None:
                display_name = email
            if not isinstance(display_name, str):
                raise Exception()
        except Exception as e:
            self.send_error(400, message='You must provide an email address, password and display name!')
            return

        if not email:
            self.send_error(400, message='The email address is invalid!')
            return

        if not phone:
            self.send_error(400, message='The phone number is invalid!')
            return

        if not address:
            self.send_error(400, message='The address is invalid!')
            return

        if not dateofbirth:
            self.send_error(400, message='The date of birth is invalid!')
            return

        if not disabilities:
            self.send_error(400, message='The disabilities filed is invalid or empty, please put NA if not applicable!')
            return

        if not password:
            self.send_error(400, message='The password is invalid!')
            return

        if not display_name:
            self.send_error(400, message='The display name is invalid!')
            return

        user = yield self.db.users.find_one({
          'email': email
        }, {})

        if user is not None:
            self.send_error(409, message='A user with the given email address already exists!')
            return

        email_enc = encrypt_aes_256(email, environ.get('KEYFILE'))
        phone_enc = encrypt_aes_256(phone, environ.get('KEYFILE'))
        address_enc = encrypt_aes_256(address, environ.get('KEYFILE'))
        disabilities_enc = encrypt_aes_256(disabilities, environ.get('KEYFILE'))
        date_of_birth_enc = encrypt_aes_256(dateofbirth, environ.get('KEYFILE'))
        salt = urandom(16)
        hashed_password = hash_password(password, salt)
        display_name_enc = encrypt_aes_256(display_name, environ.get('KEYFILE'))

        yield self.db.users.insert_one({
            'email': email_enc,
            'password': hashed_password['hashed_password'],
            'address': address_enc,
            'phone': phone_enc,
            'displayName': display_name_enc,
            'dateofbirth': date_of_birth_enc,
            'saltkey': hashed_password['salt'],
            'disabilities': disabilities_enc
        })

        self.set_status(200)
        self.response['email'] = email
        self.response['displayName'] = display_name

        self.write_json()
