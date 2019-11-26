import os
import subprocess
import sys
import requests

from flask import Flask, session, render_template, request, jsonify, abort, flash, redirect
from flask_session import Session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, login_user, logout_user, UserMixin, login_required, current_user
from sqlalchemy import create_engine, func
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm, Form
from flask_mail import Mail, Message
from wtforms import StringField, PasswordField, RadioField, BooleanField, SubmitField, SelectMultipleField, DateField
from wtforms.validators import Length, InputRequired, Email
from wtforms.widgets import TextArea
from uuid import uuid4
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
os.environ["DATABASE_URL"] = "postgres://yeunqgptxihplv:81c3415035b203f5ad010f95ae8120557827\
cbf2fe6cecec3f93c4583dc2eda5@ec2-46-51-190-87.eu-west-1.compute.amazonaws.com:5432/des0na922dmrh2"
os.environ["FLASK_DEBUG"] = '1'
os.environ["SQLALCHEMY_TRACK_MODIFICATIONS"] = 'False'

bootstrap = Bootstrap(app)

if not os.getenv("DATABASE_URL"):
	raise RuntimeError("DATABASE_URL is not set")

app.config["SESSION_PERMANENT"] = False
app.config["SESSION_TYPE"] = "filesystem"
app.config["SECRET_KEY"] = "oooooohsuchSecretsuchKey..!"
app.config["SQLALCHEMY_DATABASE_URI"] = os.getenv("DATABASE_URL")
app.config['JSON_SORT_KEYS'] = False
Session(app)

login_manager = LoginManager()
login_manager.init_app(app)

app.config.update(dict(
    DEBUG = True,
    MAIL_SERVER = 'smtp.gmail.com',
    MAIL_PORT = 587,
    MAIL_USE_TLS = True,
    MAIL_USE_SSL = False,
    MAIL_USERNAME = 'driesmans4@gmail.com',
    MAIL_PASSWORD = 'zzxx1234',
))

mail = Mail(app)

db = SQLAlchemy(app)

class LoginForm(FlaskForm):
	username = StringField("username", validators=[InputRequired(), Length(min=3, max=64)])
	password = PasswordField("password", validators=[InputRequired(), Length(max=64)])

class RegisterForm(FlaskForm):
	errormessage = "KO, STOP!"
	email = StringField("email", validators=[InputRequired(), \
		Email(message="Ok that's not your email."), Length(max=128, message=errormessage)])
	username = StringField("username", validators=[InputRequired(), Length(min=3, max=64, message=errormessage)])
	password = PasswordField("password", validators=[InputRequired(), Length(max=64, message=errormessage)])
	
class SearchForm(FlaskForm):
	searchtype = RadioField("searchtype", choices=[('isbn', 'isbn'), ('title', 'title'), ('author', 'author')], default='isbn')
	query = StringField("query", validators=[InputRequired()])

class ReviewForm(FlaskForm):
	reviewtext = StringField("Laat hier je review achter", widget=TextArea())
	score = RadioField("score", choices=[('1', '1'), ('2', '2'), ('3', '3'), ('4', '4'), ('5', '5')])

class AvailabilityForm(Form):
    date = DateField(id='datepick')


class leden(db.Model, UserMixin):
	id = db.Column(db.Integer, primary_key=True)
	username = db.Column(db.String(64), unique=True)
	email = db.Column(db.String(128), unique=True)
	password = db.Column(db.String(128))

class kampen(db.Model):
	id = db.Column(db.Integer, primary_key=True)
	isbn = db.Column(db.String(10))
	user_id = db.Column(db.Integer)
	username = db.Column(db.String)
	review_text = db.Column(db.String)
	score = db.Column(db.String)


@login_manager.user_loader
def load_user(user_id):
	return leden.query.filter_by(id=user_id).first()

@login_manager.unauthorized_handler
def unauthorized_callback():
    return redirect('/login')

@app.route("/")
def index():
	return render_template("index.html")

@app.route("/login", methods=['GET', 'POST'])
def login():
	form = LoginForm()
	if form.validate_on_submit():
		user = leden.query.filter_by(username=form.username.data).first()
		if user:
			if check_password_hash(user.password, form.password.data) and user.validated:
				login_user(user)
				return render_template("search.html", form=SearchForm())
			if not user.validated:
				return render_template("signup_success.html")
	return render_template("login.html", form=form)


@app.route("/logout", methods=['GET', 'POST'])
@login_required
def logout():
	logout_user()
	return render_template("index.html")


@app.route("/signup", methods=['GET', 'POST'])
def signup():
	form = RegisterForm()
	if form.validate_on_submit():
		username, email, password = form.username.data, form.email.data, form.password.data
		password = generate_password_hash(password)
		validation_key = uuid4().hex
		user = leden(username=username, email=email, password=password, validation_key=validation_key)
		print("link:", validation_key)
		db.session.add(user)
		db.session.commit()
		validation_mail = Message(sender="Gobbledegook Book", subject="Validate your account", recipients=[email], \
			html=render_template("validate_message.html", username=username, validation_key=validation_key))
		mail.send(validation_mail)
		return render_template("signup_success.html")
	return render_template("signup.html", form=form)


@app.route("/kampindeling", methods=['GET', 'POST'])
# @login_required
def kampindeling():
	return render_template("kampindeling.html")


@app.route("/beschikbaarheid", methods=['GET', 'POST'])
# @login_required
def beschikbaarheid():
	form = AvailabilityForm()
	if form.validate_on_submit():
		pass
	return render_template("beschikbaarheid.html", form=form)


# @app.route("/validate/<string:validation_key>")
# def validate(validation_key):
# 	user = leden.query.filter_by(validation_key=validation_key).first()
# 	if user:
# 		user.validated = True
# 		db.session.commit()
# 		return render_template("login.html", form=LoginForm())
# 	return render_template("failure.html")


# @app.route("/search", methods=['GET', 'POST'])
# @login_required
# def search():
# 	form = SearchForm()
# 	if form.validate_on_submit():
# 		searchtype, query = form.searchtype.data, form.query.data
# 		found_books = books.query.filter(getattr(books, searchtype).ilike('%' + query + '%')).all()
# 		return render_template("template.html", books=found_books)
# 	return render_template("search.html", form=form)

# @app.route("/api/<string:isbn>")
# def api(isbn):
# 	book = books.query.filter_by(isbn=isbn).first()
# 	if book:
# 		all_reviews = reviews.query.filter_by(isbn=isbn).all()
# 		count = len(all_reviews)
# 		average = sum([int(review.score) for review in all_reviews])/count
# 		return jsonify({"title":book.title, "author":book.author, "isbn":book.isbn, "year":book.year, \
# 			"review_count":count, "average_score":average})
# 	abort(404)


# @app.route("/bookpage/<string:isbn>", methods=['GET', 'POST'])
# @login_required
# def bookpage(isbn):
# 	res = requests.get(goodreads_site, params={"key": os.getenv("GOODREADS_KEY"), "isbns": isbn}).json()['books'][0]
# 	average_rating = res["average_rating"]
# 	count = res["reviews_count"]

# 	form = ReviewForm()
# 	book = books.query.filter_by(isbn=isbn).first()
# 	all_reviews = reviews.query.filter_by(isbn=isbn).all()
# 	if form.validate_on_submit():
# 		if not reviews.query.filter_by(isbn=isbn, user_id=current_user.id).all():
# 			review = reviews(user_id=current_user.id, review_text=form.reviewtext.data, \
# 				score=int(form.score.data), isbn=isbn, username=current_user.username)
# 			db.session.add(review)
# 			db.session.commit()
# 			all_reviews = reviews.query.filter_by(isbn=isbn).all()
# 		else:
# 			return render_template("failure.html")
# 	return render_template("bookpage.html", book=book, form=form, reviews=all_reviews, rating=average_rating, reviews_count=count)


# @app.route("/<string:name_str>")
# def name(name_str):
# 	return_str = ''
# 	for name in name_str.split('+'):
# 		return_str += name + ' en '
# 	return return_str[:-4]