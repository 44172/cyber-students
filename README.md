# `cyber-students`

This repository provides some sample code for the Shared Project for
Modern Cryptography and Security Management & Compliance. The project
requires Python 3 and MongoDB. The following sections briefly explain
how to setup the project on your local machine.

## Get the Sample Code

Create a [GitHub](https://github.com) account. Download and install
[git](https://git-scm.com). We will use `git` to manage our source
code. [Fork this
repository](https://docs.github.com/en/get-started/quickstart/fork-a-repo)
and clone your forked repository to your local machine.

## Setup the Project

Create a Python 3 virtual environment:

```sh
python3 -m venv project-venv
source project-venv/bin/activate
```

Install the required packages:

```sh
cd cyber-students
pip3 install -r requirements.txt
```

Download, install and start [MongoDB Community
Edition](https://www.mongodb.com/docs/manual/installation). We will
use MongoDB as our database.

Open a MongoDB shell:

```sh
mongosh
```

Create two databases with a collection named `users` in each:

```
use cyberStudents;
db.createCollection('users');

use cyberStudentsTest;
db.createCollection('users');
```

The first database will store our 'real' data. The second database
will be used by our tests.

Download and install [curl](https://curl.se). `curl` is a command-line
tool for interacting with web servers (and other protocols).

## Start the Project

The server contains functionality for:

* registering new users (`api/handlers/registration.py`)
* logging in (`api/handlers/login.py`)
* logging out (`api/handlers/logout.py`)
* displaying profile (`api/handlers/user.py`)

To start the server:

```sh
python3 run_server.py
```

The server is available on port 4000 at
http://localhost:4000/students/api. However, it is not possible to use
all of the functionality offered by the server directly using a
browser. Instead we will use `curl` to interact with the server.

### Registration

To register a new user:

```sh
curl -X POST http://localhost:4000/students/api/registration -d '{"email": "foo@bar.com", "password": "pass", "displayName": "Foo Bar"}'
```

If the registration is successful, it will confirm the email address
and the display name of the newly registered user:

```
{"email": "foo@bar.com", "displayName": "Foo Bar"}
```

If the registration is unsuccessful, for example, if you try to
register the same user twice, it will return an error message:

```
{"message": "A user with the given email address already exists!"}
```

### Logging In

To login:

```sh
curl -X POST http://localhost:4000/students/api/login -d '{"email": "foo@bar.com", "password": "pass"}'
```

If the login is successful, it will return a token and expiration
timestamp:

```
{"token": "d4a5d8b20fe143b7b92e4fba92d409be", "expiresIn": 1648559677.0}
```

A token expires and is intended to be short-lived. A token expires two
hours after login, after a logout, or if there is another login from
the same user, generating a new token.

If the login is unsuccessful, for example, if you provide an incorrect
password, it will return an error message:

```
{"message": "The email address and password are invalid!"}
```

### Displaying Profile

To display a user's profile you need to a token that has not
expired. Then you can use:

```sh
curl -H "X-TOKEN: d4a5d8b20fe143b7b92e4fba92d409be" http://localhost:4000/students/api/user
```

Note that this API call does not require the `-X POST` flag.

If successful, it will return the email address and the display name
for the user:

```
{"email": "foo@bar.com", "displayName": "Foo Bar"}
```

### Logging Out

To logout, you also need a token that has not expired. Then you can
use:


```sh
curl -X POST -H "X-TOKEN: d4a5d8b20fe143b7b92e4fba92d409be" http://localhost:4000/students/api/logout
```

## Test the Project

You can run the automated tests using:

```sh
python3 run_test.py
```

This command runs a number of automated tests in the `tests`
folder. The tests read and store data in the `cyberStudentsTest`
database only. They perform tests such as registering new users
(`tests/registration.py`), logging in (`tests/login.py`), and logging
out (`tests/logout.py`).

The project also includes a program called `run_hacker.py`. You can
run it using:

```sh
python3 run_hacker.py list
```

It displays all information stored in the MongoDB database. It
produces output similar to the following:

```
There are 1 registered users:
{'_id': ObjectId('6242d9c34536b3a16b49aa6b'), 'email': 'foo@bar.com', 'password': 'pass', 'displayName': 'Foo Bar'}
```

As you can see, all of the information is stored in the clear; there
is no encryption or password hashing. If a hacker was to compromise
the database, they could easily run a similar program to retrieve all
of the users personal information and passwords.


######################################################################################
setup to run on port 443 with SSL from self signed cert, contained on root directory "cyber-students"
public cert is cert.crt
private key is privatekey.cer
if you want to duplicate you will need to generate your own

added crypto.py
-AES256 encrypt and decrypt tool
-random salt and hash of passwords
-environment variable on computer set for encryption decryption key called "KEYFILE"

Set AES256 encryption for following fields;
email
name
address
phone
dateofbirth
disabilities

added extra field for recording random salt with user registration

setup user-api to display name and email decrypted

###################################################################################