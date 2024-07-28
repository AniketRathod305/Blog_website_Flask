from flask import Flask, render_template, request, redirect, url_for, flash

from flask_login import UserMixin, login_user, login_required, logout_user, current_user, LoginManager

from flask_sqlalchemy import SQLAlchemy

from werkzeug.security import generate_password_hash, check_password_hash

from datetime import datetime


# creating flask app
app = Flask(__name__)
DB_NAME = 'blogs.db'

# database connection
db = SQLAlchemy()
app.config['SQLALCHEMY_DATABASE_URI'] = f'sqlite:///{DB_NAME}'
app.config['SECRET_KEY'] = 'thisisasecretkey'

db.init_app(app)
# models


class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(30), nullable=False)
    email = db.Column(db.String(30), nullable=False, unique=True)
    password = db.Column(db.String(30))


class Blog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(30), nullable=False)
    category = db.Column(db.String(30), nullable=False)
    content = db.Column(db.String(500))


login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# routes


@app.route('/')
def home_page():
    return render_template('home.html', nm=current_user)


@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if (request.method == 'POST'):
        name = request.form['name']
        email1 = request.form['email']
        password1 = request.form['pwd']
        cpassword = request.form['cpwd']

        user = User(name=name, email=email1, password=generate_password_hash(
            password1, method='scrypt'))
        db.session.add(user)
        db.session.commit()
        login_user(user, remember=True)
        flash('User created successfully')
        return render_template('home.html', nm=current_user)

    return render_template('signup.html', nm=current_user)


@app.route('/login', methods=['GET', 'POST'])
def login():
    if (request.method == 'POST'):
        urname = request.form['uname']
        pwd = request.form['pwd']

        uname = User.query.filter_by(email=urname).first()
        if not uname and not check_password_hash(uname.password, pwd):
            flash('Please check your login details and try again.')
            # return redirect(url_for('auth.login'))
            return render_template('home.html', nm=current_user)
        else:
            login_user(uname, remember=True)
            print("yes")
            return render_template('home.html', nm=current_user)
    return render_template('login.html', nm=current_user)


@app.route('/logout')
@login_required
def logout():
    logout_user()
    return render_template('home.html', nm=current_user)


@app.route('/showuser', methods=['GET', 'POST'])
def showuser():
    r = User.query.all()
    return render_template('users.html', user1=r)


@app.route('/createblog', methods=['GET', 'POST'])
def create_blog():
    if (request.method == 'POST'):
        pass
    return render_template('create_blog.html', nm=current_user)


with app.app_context():
    db.create_all()
    print('Created database')

# app.debug=True


if __name__ == '__main__':
    app.run()
