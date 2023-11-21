import os
import random
from string import ascii_uppercase

import secrets
import string
from flask import (jsonify, render_template,
                   request, session, url_for, flash, redirect)
from werkzeug.urls import url_parse
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import login_user, login_required, logout_user, current_user
from sqlalchemy.sql import text
from werkzeug.utils import secure_filename
from app.models.authuser import AuthUser
from flask_socketio import (SocketIO, emit, join_room, send,
                            leave_room, rooms, disconnect)

from app import login_manager
from app import socketio
from app import app
from app import db
from app import oauth

from PIL import Image 
import PIL       

@app.route('/editmage', methods=["GET", "POST"])
def editmage():
    if request.method == 'POST':
        p = {}
        image = request.files['image']
        ext = os.path.splitext(image.filename)[1]
        if ext in ('.png', '.jpg', '.jpeg', '.gif'):
            name=generate_password_hash(str(current_user.id), method='sha256')
            filepath = os.path.join(app.static_folder, 'img/profile', f"{name}{ext}")
            image.save(filepath)
            print(f"Saved image to {filepath[9:]}")
            contact = AuthUser.query.get(current_user.id)
            p['avatar_url'] = filepath[9:]
            contact.updateprofile(** p)
            db.session.commit()

        else:
            print(f"Invalid file type: {ext}")
    return redirect(url_for('profile'))

@login_manager.user_loader
def load_user(user_id):
    # since the user_id is just the primary key of our
    # user table, use it in the query for the user
    return AuthUser.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')
    
@app.route('/boat')
def boat():
    return render_template('boat.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        remember = bool(request.form.get('remember'))

        user = AuthUser.query.filter_by(email=email).first()
        if not user:
            flash('Please check your email.')
            return redirect(url_for('login'))
        elif not check_password_hash(user.password, password):
            flash('Please check your password.')
            return redirect(url_for('login'))
        login_user(user, remember=remember)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('home')
        return redirect(next_page)

    return render_template('login.html')

@app.route('/profile')
@login_required
def profile():
   return render_template('profile.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
   
    if request.method == 'POST':
        result = request.form.to_dict()
        app.logger.debug(str(result))
 
        validated = True
        validated_dict = {}
        valid_keys = ['email', 'name', 'password']

        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            # screen of unrelated inputs
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value
            # code to validate and add user to database goes here
        app.logger.debug("validation done")
        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))
            email = validated_dict['email']
            name = validated_dict['name']
            password = validated_dict['password']
            user = AuthUser.query.filter_by(email=email).first()


            if user:
                flash('Email address already exists')
                return redirect(url_for('signup'))

            avatar_url = gen_avatar_url(email, name)
            new_user = AuthUser(email=email, name=name,
                                password=generate_password_hash(
                                    password, method='sha256'),
                                avatar_url=avatar_url,check="")
            db.session.add(new_user)
            db.session.commit()
            user = AuthUser.query.filter_by(email=email).first()
            login_user(new_user)
        return redirect(url_for('home'))
    return render_template('signup.html')

def gen_avatar_url(email, name):
    bgcolor = generate_password_hash(email, method='sha256')[-6:]
    color = hex(int('0xffffff', 0) -
                int('0x'+bgcolor, 0)).replace('0x', '')
    lname = ''
    temp = name.split()
    fname = temp[0][0]
    if len(temp) > 1:
        lname = temp[1][0]


    avatar_url = "https://ui-avatars.com/api/?name=" + \
        fname + "+" + lname + "&background=" + \
        bgcolor + "&color=" + color
    return avatar_url

@app.route('/changeprofile', methods=['GET', 'POST'])
def changeprofile():
    if request.method == 'POST':
        result = request.form.to_dict()
 
        validated = True
        validated_dict = {}
        if current_user.check != "":
            valid_keys = ['email', 'name']
        else:
            valid_keys = ['email', 'name', 'password']

        for key in result:
            app.logger.debug(str(key)+": " + str(result[key]))
            if key not in valid_keys:
                continue

            value = result[key].strip()
            if not value or value == 'undefined':
                validated = False
                break
            validated_dict[key] = value

        app.logger.debug("validation done")
        if validated:
            app.logger.debug('validated dict: ' + str(validated_dict))

            if current_user.check != "":
                validated_dict['email'] = current_user.email
            else:
                password = validated_dict['password']
                if  not check_password_hash(current_user.password, password):
                    flash('Please check your password')
                    return redirect(url_for('changeprofile'))
                validated_dict.pop('password')

            email = validated_dict['email']
            user = AuthUser.query.filter_by(email=email).first()
            if user and not(current_user.email == email):
                flash('Email address already exists')
                return redirect(url_for('changeprofile'))
            
            contact = AuthUser.query.get(current_user.id)
            contact.updateuser(** validated_dict)
            db.session.commit()

        return redirect(url_for('home'))
    return render_template('changeprofile.html')

@app.route('/logout')
@login_required
def logout():
   logout_user()
   return redirect(url_for('home'))

@app.route('/crash')
def crash():
    return 1/0

@app.route('/google/')
def google():
    oauth.register(
        name='google',
        client_id=app.config['GOOGLE_CLIENT_ID'],
        client_secret=app.config['GOOGLE_CLIENT_SECRET'],
        server_metadata_url=app.config['GOOGLE_DISCOVERY_URL'],
        client_kwargs={
            'scope': 'openid email profile'
        }
    )


   # Redirect to google_auth function
    redirect_uri = url_for('google_auth', _external=True)
    return oauth.google.authorize_redirect(redirect_uri)

@app.route('/google/auth/')
def google_auth():
    token = oauth.google.authorize_access_token()
    app.logger.debug(str(token))


    userinfo = token['userinfo']
    app.logger.debug(" Google User " + str(userinfo))
    email = userinfo['email']
    user = AuthUser.query.filter_by(email=email).first()

    if not user:
        if "family_name" in userinfo:
            name = userinfo['given_name'] + " " + userinfo['family_name']
        else:
            name = userinfo['given_name']
        userinfo['check'] = "google"
        check = userinfo['check']    
        random_pass_len = 8
        password = ''.join(secrets.choice(string.ascii_uppercase + string.digits)
                          for i in range(random_pass_len))
        picture = userinfo['picture']
        new_user = AuthUser(email=email, name=name,
                           password=generate_password_hash(
                               password, method='sha256'),
                           avatar_url=picture, check=check)
        db.session.add(new_user)
        db.session.commit()
        user = AuthUser.query.filter_by(email=email).first()
    login_user(user)
    return redirect('/')

# script for socketio
# function and arrays for room joining
rooms = {}

def random_room_name(length):
    while True:
        code = ""
        for _ in range(length):
            code += random.choice(ascii_uppercase)
        
        if code not in rooms:
            break    
    return code

@app.route('/chatroom')
@login_required
def chatroom():
    room = session.get("room")
    if room is None or room not in rooms:
        app.logger.debug("Room not found. Back to homepage")
        return redirect(url_for("home"))

    return render_template("chatroom.html", code=room, messages=rooms[room]["messages"], async_mode=socketio.async_mode)

@app.route('/randomroom')
@login_required
def random_room():
    if(len(rooms) > 0) :
        room = random.choice(list(rooms.values()))
        for i in rooms:
            if rooms[i] == room:
                room = i;
        session["room"] = room
        session["name"] = current_user.name
        socketio.emit('connect')
        return redirect(url_for("chatroom"))
    flash('no room please create room')
    return redirect(url_for('options'))

@app.route('/createroom')
@login_required
def create_room():
    room = random_room_name(4)
    new_dict = { room : {"members": 0, "messages": []} }
    rooms[room] = {"members": 0, "messages": []}
    session["room"] = room
    session["name"] = current_user.name
    
    return redirect(url_for("chatroom"))

@socketio.on("message")
@login_required
def message(data):
    room = session.get("room")
    if room not in rooms:
        return 
    
    head = current_user.avatar_url
    app.logger.debug(head)
    content = {
        "name": session.get("name"),
        "message": data["data"],
        "pic": head
    }
    
    send(content,room=room)
    rooms[room]["messages"].append(content)
    print(f"{session.get('name')} said: {data['data']}")
    app.logger.debug(session.get('name') + " said : " + data['data'] + " to room " + session.get("room"))

@socketio.on("connect")
@login_required
def connect():
    room = session.get("room")
    name = session.get("name")
    if not room or not name:
        return
    if room not in rooms:
        leave_room(room)
        return
    
    join_room(room)
    # send({"name": name, "message": "has entered the room"}, to=room)
    rooms[room]["members"] += 1
    print(f"{name} joined room {room}")

@socketio.on("disconnect")
@login_required
def disconnect():
    room = session.get("room")
    name = session.get("name")
    leave_room(room)

    if room in rooms:
        rooms[room]["members"] -= 1
        if rooms[room]["members"] <= 0:
            del rooms[room]
    
    # send({"name": name, "message": "has left the room"}, to=room)
    print(f"{name} has left the room {room}")

@app.route('/option')
def options():
    session['room'] = ''
    return render_template('option.html')