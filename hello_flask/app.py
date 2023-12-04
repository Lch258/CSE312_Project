import html
import hashlib
import os
import time
import bcrypt
import json
from bson.objectid import ObjectId
from flask import Flask, make_response, request, redirect, render_template, send_from_directory, session, jsonify, \
    url_for
from pymongo import MongoClient
from uuid import uuid4
from flask_socketio import SocketIO, emit
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from flask_mail import Mail, Message
from itsdangerous import URLSafeTimedSerializer

import os

mongo_client = MongoClient("mongo")
db = mongo_client["cse312"]  # database

security_collection = db["security"]  # collection in the database for usernames/salts/password hashes/auth hashes
post_collection = db["post"]
quiz_collection = db['quiz']
score_collection = db['score']  # used to track user's score

app = Flask(__name__)  # initialise the applicaton
app.config['SERVER_NAME'] = 'siliconsages.software'
app.secret_key = '123456789'
app.config["SECURITY_PASSWORD_SALT"] = "123456789123456789123456789"
socketio = SocketIO(app, async_mode='eventlet', transports=['websocket'])

LIMIT = "50 per 10 seconds"


limiter = Limiter(
    get_remote_address,
    app=app,
    default_limits=[LIMIT],
    storage_uri="memory://",
)

blocked = {}

app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USERNAME'] = "siliconsages@gmail.com"
app.config['MAIL_PASSWORD'] = "zeua cdhx zecl devp"
app.config['MAIL_DEFAULT_SENDER'] = "siliconsages@gmail.com"
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USE_SSL'] = False
mail = Mail(app)

# post_collection.delete_many({})  # REMOVE THIS LINE
# security_collection.delete_many({})  # REMOVE THIS LINE
# quiz_collection.delete_many({})

global score


@app.before_request
def before_request():
    ip_address = get_remote_address()
    if ip_address in blocked and blocked[ip_address] > time.time():
        return betterMakeResponse("Too many requests, IP is blocked.", "text/plain", 429)


start_times = {}


@app.route("/")
@limiter.limit("10 per 10 seconds")
def home():
    return htmler("templates/index.html")


@app.route("/login.html")
@limiter.limit("10 per 10 seconds")
def logger():
    return htmler("templates/login.html")


@app.route("/index.css")
@limiter.limit("10 per 10 seconds")
def indexCsser():
    return csser("templates/index.css")


@app.route("/posts.html")
@limiter.limit("50 per 10 seconds")
def posterhtml():
    return htmler("templates/posts.html")


@app.route("/posts.css")
@limiter.limit("50 per 10 seconds")
def posterthingy():
    return csser("templates/posts.css")


def userLocator():
    auth = request.cookies.get('auth')  # gets auth plaintext
    username = "Guest"  # default is guest
    if auth != None:  # if there is an auth cookie, gets username
        hashAuth = hashSlingingSlasher(auth)  # hashes auth plaintext
        record = security_collection.find_one(
            {"hashed authentication token": hashAuth})  # finds user record in database
        username = record["username"]  # gets username from user record
    return username


@app.route("/functions.js")
@limiter.limit("10 per 10 seconds")
def jsFunctions():
    jsCodeStream = open("static/functions.js", "rb").read()
    return betterMakeResponse(jsCodeStream, "text/javascript")


@app.route("/background-posts.jpg")
def background():
    imageCodeStream = open("templates/background-posts.jpg", "rb").read()
    return betterMakeResponse(imageCodeStream, "image/jpg")


@app.route("/visit-counter")
@limiter.limit("50 per 10 seconds")
def cookie():
    timesvisited = 1
    if "visits" in request.cookies:
        stringNumber = request.cookies.get("visits")
        timesvisited = int(stringNumber) + 1  # update
    visitstring = "Times Visited: " + str(timesvisited)
    response = make_response(visitstring)
    response.set_cookie("visits", str(timesvisited), max_age=3600)
    response.headers.set("X-Content-Type-Options", "nosniff")
    return response


@app.route("/guest", methods=['POST'])
@limiter.limit("10 per 10 seconds")
def guestMode():
    token_str = request.cookies.get("auth")  # gets auth plaintext cookie
    response = make_response(redirect("/view_quizzes.html", 301))  # makes redirect response object
    if token_str != None:  # if there is a user signed in
        response.delete_cookie("auth")  # remove auth cookie (sign user out)
    return response  # return posts.html


@app.route("/register", methods=['POST'])
@limiter.limit("10 per 10 seconds")
def register():
    username = html.escape(str(request.form.get('reg_username')))  # working, gets username from request
    bPass = str(request.form.get('reg_password')).encode()  # password from request in bytes
    email = html.escape(str(request.form.get('reg_email')))  # email address from request
    salt = bcrypt.gensalt()  # salt used to hash password (we need this later)
    hashPass = bcrypt.hashpw(bPass, salt)  # salted and hashed password

    registeredUsers = list(security_collection.find(
        {'username': username}))  # looks for the username in the database, needs to be converted to list to use
    if len(registeredUsers) != 0:  # this list is always len 1, the only element is one dictionary containing each user record
        return redirect("/", 301)  # username is not available
    else:
        security_collection.insert_one({
            "username": username,
            "salt": salt,
            "hpw": hashPass,
            "email": email,
            "email_verified": False
        })  # username is unique so it is inserted into the database
        # score_collection.insert_one({"username": username, "score": 0})
        return redirect("/login.html", 301)  # username is available


@app.route("/login", methods=['POST'])
@limiter.limit("10 per 10 seconds")
def login():
    username = html.escape(str(request.form.get('log_username')))  # gets username from the username textbox
    password = str(request.form.get('log_password')).encode()  # gets password from the password textbox
    userRecord = list(security_collection.find(
        {"username": username}))  # looks up the username in the database and gets the unique user data
    # ^converts the user record into a list with ONE dictionary containing all of the user information
    # referencing the user info will always need to be userRecord[0], this list will never be greater than size 1

    if len(userRecord) != 0:
        userInfo = userRecord[0]  # used to simplify notation, user information is always in index 0
        salt = userInfo["salt"]  # gets salt from the database record
        realHash = userInfo["hpw"]  # gets the sha256 hash of the user's password from the database record
        passHash = bcrypt.hashpw(password, salt)  # gets the sha256 hash of the ENTERED password from the textbox
        if passHash == realHash:  # user is logged in if both hashes match
            token = str(uuid4())  # generate a random token using uuid4
            tokenHash = hashSlingingSlasher(token)  # hash this token for the database
            security_collection.update_one({"username": username, "salt": salt, "hash": realHash},
                                           {"$set": {"hashed authentication token": tokenHash}},
                                           True)  # updates database to include authenticated token hash in the record
            response = make_response(
                redirect('/view_quizzes', 301))  # generates response that will redirect to the posts page
            response.set_cookie("auth", token, 3600, httponly=True)  # sets authentication token as a cookie

            session['logged_in'] = True
            session['email_verified'] = userInfo.get('email_verified', False)
            session['email'] = userInfo.get('email', False)
            session['username'] = userInfo.get('username', False)

            return response
        else:
            return redirect("/login.html", 301)  # incorrect password
    else:
        return redirect("/login.html", 301)  # username not found


@app.route("/get_posts", methods=['GET'])
@limiter.limit("50 per 10 seconds")
def get_posts():  # UNTESTED (pulled from most recent push)
    posts = list(post_collection.find({}))
    for post in posts:
        post["_id"] = str(post["_id"])
    return json.dumps(posts)


@app.route("/add_post", methods=['POST'])  # stores posts in the database
@limiter.limit("50 per 10 seconds")
def addPost():
    token_str = request.cookies.get('auth')  # token is a now a string in the database
    try:
        token = str(token_str)  # should already be str, if None it will fail
    except TypeError:  # if None no user log in
        return betterMakeResponse("No user login", "text/plain", 401)
    hashedToken = hashSlingingSlasher(token)  # hashes the token using sha256 (no salt)
    userData = security_collection.find_one(
        {"hashed authentication token": hashedToken})  # gets all user information from security_collection
    if not userData:
        return betterMakeResponse("Invalid token", "text/plain", 401)

    username = userData.get('username')  # gets username from security_collection
    postData = request.json  # parses the post json data
    title = postData['title']  # takes the title from the post data
    message = postData['message']  # takes the message from the post data
    post_collection.insert_one({  # inserts the post into the database
        "title": html.escape(title),
        "message": html.escape(message),
        "username": html.escape(username),
        "mesID": str(uuid4()),
        "likes": str(0),
        "userswholiked": str("")  # string 'list' of users who liked the post. Initalize as empty.
    })
    return betterMakeResponse("Post Success", "text/plain")


@app.route('/like', methods=['POST'])
@limiter.limit("50 per 10 seconds")
def like():
    token_str = request.cookies.get('auth')  # token is a now a string in the database
    try:
        token = str(token_str)  # should already be str, if None it will fail
    except TypeError:  # if None no user log in
        return betterMakeResponse("No user login", "text/plain", 401)

    hashedToken = hashSlingingSlasher(token)  # hashes the token using sha256 (no salt)
    userData = security_collection.find_one(
        {"hashed authentication token": hashedToken})  # gets all user information from security_collection
    messageID = request.json
    print(messageID)
    print(post_collection.find_one({"mesID": (messageID['postid'])}))
    post = post_collection.find_one({"mesID": (messageID['postid'])})  # post that was clicked on
    likedusers = str(post['userswholiked'])
    likedusersList = likedusers.split(",")
    likes = post.get('likes')

    if (str(userData['username']) in likedusersList) == False:  # user has not liked post
        post_collection.update_one({"mesID": messageID['postid']}, {"$set": {"likes": str((int(likes) + 1))}})
        likedusersList.append(userData['username'])
        listasString = ','.join(likedusersList)
        post_collection.update_one({"mesID": messageID['postid']}, {"$set": {"userswholiked": listasString}})
        return betterMakeResponse("User liked", "text/plain", 200)
    else:  # unlike part
        post_collection.update_one({"mesID": messageID['postid']}, {"$set": {"likes": str((int(likes) - 1))}})
        likedusersList.remove(userData['username'])
        listasString = ','.join(likedusersList)
        post_collection.update_one({"mesID": messageID['postid']}, {"$set": {"userswholiked": listasString}})
        return betterMakeResponse("User did not like", "text/plain", 200)


@app.route('/create_quiz', methods=['GET', 'POST'])
@limiter.limit("10 per 10 seconds")
def create_quiz():
    authenticatedUser = False  # false if guest
    username = userLocator()
    if username != 'Guest':
        authenticatedUser = True

    if request.method == 'POST':

        if authenticatedUser:
            # Get quiz data from the form

            question = request.form['question']
            option1 = request.form['option1']
            option2 = request.form['option2']
            option3 = request.form['option3']
            option4 = request.form['option4']
            correct_answer = request.form['correct_answer']
            # Save the quiz data to the MongoDB database
            quiz_data = {
                'username': userLocator(),
                'question': html.escape(question),
                'option1': html.escape(option1),
                'option2': html.escape(option2),
                'option3': html.escape(option3),
                'option4': html.escape(option4),
                'correct_answer': html.escape(correct_answer),
                'answer_times': 0,
                'correct_times': 0,
                # initialize as empty string. Updating this would be adding in following format: 'username:score,'
                'attemptedUsers': ''
            }
            inserted = quiz_collection.insert_one(quiz_data)
            _id = str(inserted.inserted_id)
            start_time = time.time()
            start_times[_id] = start_time
            # Handle quiz image upload
            if 'quiz_image' in request.files:
                quiz_image = request.files['quiz_image']
                if quiz_image.filename == '':
                    return redirect('/view_quizzes', 301)
                print(quiz_image)
                _id = inserted.inserted_id
                dir = '/uploaded'
                if not os.path.exists(dir):
                    os.makedirs(dir)
                image_filename = str(_id) + '.jpg'
                filepath = os.path.join(dir, image_filename)
                quiz_image.save(filepath)
                quiz_collection.update_one({'_id': _id}, {'$set': {'image': image_filename}})
            return redirect('/view_quizzes', 301)
        else:  # guest so just redirect to Register
            return redirect('/', 301)
    else:
        # If it's a get request, render the 'create_quiz.html' template
        return render_template('create_quiz.html')


@app.route('/uploaded_file/<filename>')
@limiter.limit("50 per 10 seconds")
def sendimage(filename):
    return send_from_directory('/uploaded', filename)


@app.route('/view_quizzes', methods=['GET'])
@limiter.limit("10 per 10 seconds")
def view_quizzes():
    quizzes = quiz_collection.find({'notdisplay': {'$ne': True}})
    return render_template('view_quizzes.html', quizzes=quizzes)


@app.route('/check_answer/<quiz_id>', methods=['POST'])
@limiter.limit("10 per 10 seconds")
def check_answer(quiz_id):
    if request.method == 'POST':
        selected_choice = request.form.get('choice')  # uses get in case there is no choice selected
        if type(selected_choice) == None:  # if user does not pick an option, refreshes the page
            return make_response(redirect("/view_quizzes.html", 301))  # fixes no choice crashes server bug

        # Retrieve the quiz from the database based on quiz_id
        quiz = quiz_collection.find_one({"_id": ObjectId(quiz_id)})

        # Check if the selected choice is the correct answer
        is_correct = (selected_choice == quiz['correct_answer'])

        token_str = request.cookies.get('auth')  # token is a now a string in the database
        try:
            token = str(token_str)  # should already be str, if None it will fail
        except TypeError:  # if None no user log in
            return betterMakeResponse("No user login", "text/plain", 401)
        hashedToken = hashSlingingSlasher(token)  # hashes the token using sha256 (no salt)
        userData = security_collection.find_one(
            {"hashed authentication token": hashedToken})  # gets all user information from security_collection
        if not userData:
            return betterMakeResponse("Unauthenticated User", "text/plain", 401)

        username = userData['username']

        # if quiz creator answer his own question, then throw an error
        if username == quiz['username']:
            response_message = "Creators can't answer their own questions"
            return render_template('answer_result.html', message=response_message, return_url='/view_quizzes')

        score_record = score_collection.find_one({"username": username})

        if not score_record:  # initial user's score
            score_record = {
                "username": username,
                "score": 0,
                "answered_quizzes": [],
                "quizToGrade": {}
            }
            score_collection.insert_one(score_record)

        if quiz_id in score_record.get('answered_quizzes', []):  # Each question can only be answered once
            # return render_template('___.html') html contain "You have already answered this quiz." text and return home button
            response_message = "You have already answered this quiz."
            return render_template('answer_result.html', message=response_message, return_url='/view_quizzes')

        new_score = score_record['score']

        zeroOrOneScore = 0
        if is_correct:
            zeroOrOneScore = 1
            # get the user's score db, and add 1
            new_score = new_score + 1
            # response_message = "Correct. Score: " + str(new_score)
            response_message = "Correct. Score: 1"

            correct_times = quiz['correct_times'] + 1

            quiz_collection.update_one(  # update score to db and quiz id
                {"_id": ObjectId(quiz_id)},
                {
                    "$set": {"correct_times": correct_times},
                }
            )

        else:
            # get the user's score db, and minus 1
            # new_score = score_record['score'] - 1
            response_message = "Incorrect. Score: 0"

        answer_times = quiz['answer_times'] + 1

        quiz_collection.update_one(  # update score to db and quiz id
            {"_id": ObjectId(quiz_id)},
            {
                "$set": {"answer_times": answer_times},
            }
        )

        score_collection.update_one(  # update score to db and quiz id
            {"username": username},
            {
                "$set": {"score": new_score},
                "$push": {"answered_quizzes": quiz_id},
                "$set": {"quizToGrade." + quiz_id: str(zeroOrOneScore)}
            },
            upsert=True
        )
        # return render_template('___.html') html contain the score, whether the answer is correct, and return button to view quiz page
        return render_template('answer_result.html', message=response_message, return_url='/view_quizzes')


@app.route('/gradebook', methods=['GET'])
@limiter.limit("10 per 10 seconds")
def gradebook():
    token_str = request.cookies.get('auth')  # token is a now a string in the database
    try:
        token = str(token_str)  # should already be str, if None it will fail
    except TypeError:  # if None no user log in
        return betterMakeResponse("No user login", "text/plain", 401)
    hashedToken = hashSlingingSlasher(token)  # hashes the token using sha256 (no salt)
    userData = security_collection.find_one(
        {"hashed authentication token": hashedToken})  # gets all user information from security_collection
    if not userData:
        return betterMakeResponse("Unauthenticated User", "text/plain", 401)

    username = userData['username']

    quizzesMadeByUser = quiz_collection.find({"username": username})  # this is quizzes that user made

    takenQuizzes = []
    scoreRecord = score_collection.find_one({"username": username})
    keys = None

    if (scoreRecord != None):
        keysObject = scoreRecord['quizToGrade']
        if (keysObject != None):
            keys = keysObject.keys()
            for key in keys:
                originalQuiz = quiz_collection.find_one({"_id": ObjectId(key)})
                originalQuiz['scored'] = scoreRecord['quizToGrade'][key]
                takenQuizzes.append(originalQuiz)

    return render_template('gradebook.html', quizzes=quizzesMadeByUser, takenQuizzes=takenQuizzes)


def hashSlingingSlasher(token):  # wrapper for hashlib256
    object256 = hashlib.sha256()
    object256.update(token.encode())
    tokenHash = object256.digest()
    return (tokenHash)


def htmler(filename):  # wrapper for opening html files as bytes
    file = open(filename, "rb").read()  # opens filename as bytes and reads the contents
    return betterMakeResponse(file, "text/html")  # uses betterMakeResonse wrapper to make a response


def csser(filename):  # wrapper for opening css files
    file = open(filename, "rb").read()  # opens filename as bytes and reads the contents
    return betterMakeResponse(file, "text/css")  # uses betterMakeResponse wrapper to make a response


def betterMakeResponse(file, ct, status=200):  # takes in all necessary info to make a response
    response = make_response(file, status)
    # file is either a file to send or a string to encode
    # default status is 200 unless specified otherwise
    response.headers.set("Content-Type", ct)  # sets content type header to the content type string ct
    response.headers.set("X-Content-Type-Options", "nosniff")  # sets nosniff header
    return response  # returns response object


@socketio.on("refresh_clients")  # will help with live updates in the future, for now this does not fully work
def refreshClients():  # should not be accessible from the client at this point
    print("got here")
    emit('init_r', broadcast=True)


@socketio.on('get_remaining_time')
def get_remaining_time(data):
    quiz_id = data['quiz_id']

    if quiz_id not in start_times:
        start_times[quiz_id] = time.time()

    start_time = start_times[quiz_id]
    current_time = time.time()
    time_last = (current_time - start_time)
    remaining_time = int(60 - time_last)

    if remaining_time < 0:
        quiz_collection.update_one({'_id': ObjectId(quiz_id)}, {'$set': {'notdisplay': True}})
        emit('refresh', broadcast=True)  # broadcast flag is for sending to ALL clients and not just one
    emit('update_remaining_time', {'quiz_id': quiz_id, 'remaining_time': remaining_time}, broadcast=True)


@app.errorhandler(429)
def ratelimit_error(e):
    ip_address = get_remote_address()
    blocked[ip_address] = time.time() + 30
    return betterMakeResponse("Too many requests, IP is blocked.", "text/plain", 429)


def send_verification_email(email):
    serializer = URLSafeTimedSerializer(app.config["SECRET_KEY"])
    token = serializer.dumps(email, salt=app.config["SECURITY_PASSWORD_SALT"])
    print(token)
    confirm_url = url_for('confirm_email', token=token, _external=True)
    html = render_template('email_verification.html', confirmurl=confirm_url)
    msg = Message(
        "Confirm your email",
        recipients=[email],
        html=html,
        sender=app.config['MAIL_DEFAULT_SENDER']
    )
    mail.send(msg)


@app.route('/confirm/<token>')
def confirm_email(token):
    print(session)
    session['email_verified'] = True
    email = session.get("email")
    security_collection.update_one({"email": email}, {"$set": {"email_verified": True}})
    # confirm token logical here
    return "Confirmed"


@app.route('/send_verification')
def send_verification():
    print(session)
    email = session.get('email')
    send_verification_email(email)
    return "Verification email sent"


if __name__ == '__main__':
    socketio.run(app, host='0.0.0.0', port=8080, debug=True)  # any time files change automatically refresh