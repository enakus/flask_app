from flask import Flask, render_template, request, redirect, url_for, session
from flask_mysqldb import MySQL
import MySQLdb.cursors
import re

def uuint():
    print("[IMPORT] Importing dblib...")
    
def get_all_shares(mysql, session_data):
	msg = ""
	shares_list = []
	username = session_data.get('username')
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT * FROM fileshares WHERE username = % s", (username, ))
	shares = cursor.fetchall()
	if shares:
		for share in shares:
			shares_list.append(share["sharename"])
		return shares_list
	else:
		msg = "[ERROR]: smthg gone wrong lol"
	return shares_list
	
def get_share_author(mysql, session_data, sharename):
	username = session_data.get('username')
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT username FROM fileshares WHERE sharename = % s", (sharename, ))
	share_user = cursor.fetchone()
	if share_user:
		#print("In [if share_user:]")
		if (share_user['username'] == username):
			#print(f"    TRUE ({share_user} == {username})")
			return True
		else:
			#print(f"    FALSE ({share_user} != {username})")
			return False
	else:
		#print("In first [else:]")
		return False

def get_all_commets(mysql, sharename):
	comments_list = []
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	cursor.execute("SELECT * FROM comments WHERE sharename = % s", (sharename, ))
	comments = cursor.fetchall()
	if comments:
		for comment in comments:
			strr = f"{comment['created_at']} | {comment['username']} | {comment['content']}"
			comments_list.append(strr)
		return comments_list
	else:
		return comments_list

def add_comment(mysql, comment, sharename, username):
	cursor = mysql.connection.cursor(MySQLdb.cursors.DictCursor)
	if len(comment) != 0 and len(sharename) != 0 and len(username) != 0:
		par_com = comment.strip(); par_shr = sharename; par_usr = username;
		cursor.execute("INSERT INTO comments (content, username, sharename) VALUES ( % s, % s, % s)", (par_com, par_usr, par_shr, ))
		mysql.connection.commit()
		return True
	else:
		#print("In first [else:]")
		return False
