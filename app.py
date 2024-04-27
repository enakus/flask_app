from flask import Flask, render_template, request, redirect, url_for, session, abort, make_response, jsonify, send_file
from flask_mysqldb import MySQL
from werkzeug.utils import secure_filename
from io import BytesIO
import subprocess
import zipfile
import bcrypt
import MySQLdb.cursors
import re
import os

#============================================
#		   LIBS
#============================================
from libs.dblib import *
from libs.filelib import *

#============================================
#		  FUNCS
#============================================
def get_hashed_password(plain_text_password):
    return bcrypt.hashpw(plain_text_password, bcrypt.gensalt())

def check_password(plain_text_password, hashed_password):
    return bcrypt.checkpw(plain_text_password, hashed_password)

app = Flask(__name__)
 
app.secret_key = os.environ['SKEY_FLASK']

app.config['MYSQL_HOST'] = os.environ['MYSQL_HOST']
app.config['MYSQL_USER'] = os.environ['MYSQL_USER']
app.config['MYSQL_PASSWORD'] = os.environ['MYSQL_PASSWORD']
app.config['MYSQL_DB'] = os.environ['MYSQL_DB']

app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024
 
mysql = MySQL(app)

def check_access(session_data, page):
	print(f"[DEBUG]: Checking access of user '{session_data.get('username')}' to '{page}'")
	if session_data.get('loggedin'):
		print("    [OK!]: Logged in")
		return True
	else:
		print("    [ERROR]: User didn't logged in!")
		return False

@app.route('/')
@app.route('/login', methods =['GET', 'POST'])
def login():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form:
        username = request.form['username']
        password = request.form['password'].strip().encode('utf-8')
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account and check_password(password, account['password'].strip().encode('utf-8')):
            session['loggedin'] = True
            session['id'] = account['id']
            session['username'] = account['username']
            session['role'] = account['role']
            if(session['role'] == "admin"):
            	print(f"[DEB]: Admin '[{session['id']}]: {session['username']}' logged in!");
            else:
            	print(f"[DEB]: User '[{session['id']}]: {session['username']}' logged in!");
            msg = '[OK]: Logged in successfully !'
            return render_template('index.html', msg = msg)
        else:
            msg = '[ERROR]: Incorrect credentials!'
    return render_template('login.html', msg = msg)
 
@app.route('/logout')
def logout():
    session.pop('loggedin', None)
    session.pop('id', None)
    session.pop('username', None)
    return redirect(url_for('login'))
 
@app.route('/register', methods =['GET', 'POST'])
def register():
    msg = ''
    if request.method == 'POST' and 'username' in request.form and 'password' in request.form and 'email' in request.form :
        username = request.form['username'].strip()
        password = get_hashed_password(request.form['password'].strip().encode('utf-8'))
        email = request.form['email']
        cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
        cursor.execute('SELECT * FROM accounts WHERE username = % s', (username, ))
        account = cursor.fetchone()
        if account:
            msg = '[ERROR]: Account already exists !'
        elif not re.match(r'[^@]+@[^@]+\.[^@]+', email):
            msg = '[ERROR]: Invalid email address !'
        elif not re.match(r'[A-Za-z0-9]+', username):
            msg = '[ERROR]: Username must contain only characters and numbers !'
        elif not username or not password or not email:
            msg = '[ERROR]: Please fill out the form !'
        else:
            cursor.execute('INSERT INTO accounts VALUES (NULL, % s, % s, % s, % s)', (username, password, email, "user", ))
            mysql.connection.commit()
            msg = 'You have successfully registered !'
    elif request.method == 'POST':
        msg = 'Please fill out the form !'
    return render_template('register.html', msg = msg)
    
@app.route('/fileshares', methods =['GET', 'POST'])   
def fileshare():
	if check_access(session, "fileshares"):
		pass
	else:
		return render_template("login.html", msg = "You must log in to get this page!") 
	shares = get_all_shares(mysql, session)
	msg = ""
	#print("[SHARES]: "); print(shares);
	if request.method == "POST" and "sharename" in request.form:
		sharename = request.form["sharename"]
		cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor) 
		cursor.execute("SELECT * FROM fileshares WHERE sharename = % s AND username = % s", (sharename, session["username"]))
		exists_sharename = cursor.fetchone()
		if exists_sharename:
			msg = "[ERROR]: Fileshare already exists!"
		elif not re.match(r'[A-Za-z0-9]+', sharename):
			msg = "[ERROR]: Fileshare should contain only letters and numbers!"
		elif not sharename:
			msg = '[ERROR]: Please fill out the form !'
		else:
			print(f"[DEB]: Creating fileshare: {sharename}")
			cursor.execute("INSERT INTO fileshares (sharename, username) VALUES (% s, % s)", (sharename, session["username"], ))
			mysql.connection.commit(); path = f"./shares/{sharename}"
			if not os.path.exists(path):
				os.mkdir(path)
			else:
				msg = "[ERROR]: Share already exists!"
			msg = f"[OK]: Fileshare '{sharename}' created!"
					
	return render_template("fileshares.html", msg = msg, shares = shares)	
	
@app.route('/share/<sharename>', methods = ['GET', 'POST'])
def share(sharename):
	if check_access(session, f"/share/{sharename}"):
		pass
	else:
		return render_template("login.html", msg = "You must log in to get this page!")
		
	if get_share_author(mysql, session, sharename):
		files = get_share_files(f"shares/{sharename}")
		comments = get_all_commets(mysql, sharename)
		#print(comments)
		return render_template("share.html", sharename = sharename, files = files, comments = comments)
	else:
		return fileshare()

@app.route('/post', methods = ['POST'])
def post_comment():
	if check_access(session, f"/post"):
		pass
	else:
		return render_template("login.html", msg = "You must log in to get this page!")

	if request.method == "POST" and "comment" in request.form and "sharename" in request.form:
		if (get_share_author(mysql, session, request.form['sharename'])):
			ret = add_comment(mysql, request.form["comment"], request.form["sharename"], session.get("username"))
			if ret:
				#print(f"[DEB]: Comment submited! to {request.form['sharename']}")
				return render_template("error.html", msg = f"[DEB]: Comment submited to {request.form['sharename']}!")
			else:
				#print(f"[ERROR]: Error occured while submiting comment to {request.form['sharename']}!")
				return render_template("error.html", msg = f"[ERROR]: Error occured while submiting comment to {request.form['sharename']}!")
			
		else:
			return render_template("error.html", msg = "[ERROR]: You can't access and post on other people shares!")
			
	return render_template(f"error.html", msg = "[ERROR]: smthg gone wrong, lol")
	
	
@app.route('/upload', methods = ['POST'])
def upload_file():
	if check_access(session, f"/upload_file"):
		pass
	else:
		return render_template("login.html", msg = "You must log in to get this page!")

	if request.method == "POST" and "file" in request.files and "sharename" in request.form:
		if (get_share_author(mysql, session, request.form['sharename'])):
			        ofile = request.files['file']
        			if ofile and allowed_file(ofile.filename):
        				sec_file = secure_filename(ofile.filename)
        				ofile.save(os.path.join(f"./shares/{request.form['sharename']}", sec_file))
        				return render_template("error.html", msg = "[OK]: File successfully uploaded!")
        			else:
        				return render_template("error.html", msg = "[ERROR]: Only PNG, JPG, JPEG, GIF allowed!")
			
		else:
			return render_template("error.html", msg = "[ERROR]: You can't upload files to other people shares!")
			
	#return render_template(f"share.html", sharename = request.form["sharename"], files = get_share_files(f"./shares/{request.form['sharename']}"))

@app.route('/download', methods = ['POST'])
def download_share():
	fileName = f"{request.form['sharename']}_dump.zip"
	memory_file = BytesIO()
	file_path = f"./shares/{request.form['sharename']}"
	with zipfile.ZipFile(memory_file, 'w') as zipf:
		for root, dirs, files in os.walk(file_path):
			for ofile in files:
				zipf.write(os.path.join(root, ofile))
	memory_file.seek(0)
	return send_file(memory_file, mimetype="application/zip", download_name = fileName, as_attachment=True)

@app.route('/admin', methods = ['GET', 'POST'])
def admin():
	if check_access(session, "/admin") and session.get("role") == "admin":
		if request.method == "GET":
			return render_template("admin.html")
		elif request.method == "POST" and "command":
			try:
			    result = subprocess.check_output(request.form["command"], shell=True, text=True)
			    return render_template("admin.html", msg = result)
			except subprocess.CalledProcessError as e:
			    return render_template("admin.html", msg = f"Error executing command: {e}")
	else:
		return render_template("login.html", msg = "[ERROR]: You can't access this page!")

@app.errorhandler(413)
def too_large(e):
    return render_template("error.html", msg = "[ERROR]: File is larger than 16MB!")

	
