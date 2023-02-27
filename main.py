from flask import Flask, render_template, redirect, url_for, abort, flash
from flask_bootstrap import Bootstrap
from flask_login import UserMixin, login_user, LoginManager, current_user, logout_user, login_required
from forms import RegisterForm, CreatePostForm, LoginForm, CommentForm
from flask_ckeditor import CKEditor
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.orm import relationship
from werkzeug.security import generate_password_hash, check_password_hash
from datetime import datetime
import os
from functools import wraps

# Configure Flask
app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY')

# Adds CKEditor to app
ckeditor = CKEditor(app)

# Adds Bootstrap to app
Bootstrap(app)

# Links app with SQL database
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL', 'sqlite:///blog.db')
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

# Allows people to be logged in
login_manager = LoginManager()
login_manager.init_app(app)

year = datetime.now().year


class User(UserMixin, db.Model):
    __tablename__ = 'users'
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(250), nullable=False)
    email = db.Column(db.String(250), nullable=False)
    password = db.Column(db.String(250), nullable=False)
    posts = relationship("BlogPost", back_populates='author')
    comments = relationship("Comment", back_populates='comment_author')


class BlogPost(db.Model):
    __tablename__ = "blog_posts"
    id = db.Column(db.Integer, primary_key=True)
    author = relationship("User", back_populates="posts")
    title = db.Column(db.String(250), unique=True, nullable=False)
    subtitle = db.Column(db.String(250), nullable=False)
    date = db.Column(db.String(250), nullable=False)
    body = db.Column(db.Text, nullable=False)
    img_url = db.Column(db.String(250), nullable=False)
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    comments = relationship("Comment", back_populates='parent_post')
    genre = db.Column(db.String, nullable=False)


class Comment(db.Model):
    __tablename__ = 'comments'
    id = db.Column(db.Integer, primary_key=True)
    text = db.Column(db.Text, nullable=False)
    comment_author = relationship("User", back_populates='comments')
    author_id = db.Column(db.Integer, db.ForeignKey('users.id'))
    post_id = db.Column(db.Integer, db.ForeignKey('blog_posts.id'))
    parent_post = relationship("BlogPost", back_populates='comments')


# This created the database using the classes above
with app.app_context():
    db.create_all()


def admin_only(function):
    @wraps(function)
    def wrapper(*args, **kwargs):
        try:
            if current_user.id == 1:
                return function(*args, **kwargs)
            else:
                return abort(403)
        except AttributeError:
            return abort(403)
    return wrapper


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(user_id)


# Home page
@app.route('/', methods=["GET", "POST"])
def home():
    try:

        posts = BlogPost.query.all()
        return render_template('index.html',
                               year=year,
                               user=current_user,
                               logged_in=current_user.is_authenticated,
                               posts=posts)
    except Exception as e:
        print('Error returning the home page')
        print(f'Here is the error: {e}')


# Register page
@app.route('/register', methods=["GET", "POST"])
def register():
    form = RegisterForm()
    if form.validate_on_submit():
        new_user = User()
        new_user.name = form.name.data
        if not User.query.filter_by(email=form.email.data).first():
            new_user.email = form.email.data
            new_user.password = generate_password_hash(password=form.password.data,
                                                       method='pbkdf2:sha256',
                                                       salt_length=8)
            db.session.add(new_user)
            db.session.commit()
            login_user(new_user)
            return redirect(url_for('home'))
        else:
            flash("This email is already registered in our database. Try logging in instead.")
            return redirect(url_for('login'))
    return render_template('register.html',
                           year=year,
                           form=form,
                           logged_in=current_user.is_authenticated,
                           user=current_user)


# Login page
@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data).first()
        if user:
            if check_password_hash(user.password, form.password.data):
                login_user(user)
                return redirect(url_for('home'))
            else:
                flash('Incorrect password. Try again')
        else:
            flash('There is no account for that user')
    return render_template('login.html', year=year, form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('home'))


# Admin page to make new posts
@app.route('/new-post', methods=['GET', 'POST'])
@admin_only
def new_post():
    form = CreatePostForm()
    if form.validate_on_submit():
        post = BlogPost()
        # post.author = current_user.name
        post.title = form.title.data
        post.subtitle = form.subtitle.data
        post.genre = form.genre.data
        post.img_url = form.img_url.data
        post.body = form.body.data
        post.date = datetime.today().strftime('%m/%d/%Y')
        db.session.add(post)
        db.session.commit()
        return redirect(url_for('home'))
    return render_template('make-post.html', form=form, logged_in=current_user.is_authenticated)


@app.route("/delete/<int:post_id>")
@admin_only
def delete_post(post_id):
    post_to_delete = BlogPost.query.get(post_id)
    db.session.delete(post_to_delete)
    db.session.commit()
    return redirect(url_for('home'))


@app.route("/post/<int:post_id>")
def show_post(post_id):
    requested_post = BlogPost.query.get(post_id)
    return render_template('post.html', post=requested_post)


@app.route('/post-category/<category>')
def post_category(category):
    posts = BlogPost.query.filter_by(genre=category)
    category_name = category
    if category == 'Random Thoughts':
        category = 'Random-Thoughts'
        category_name = 'Random Thoughts'
    elif category == 'Tech':
        category_name = 'Technology'
    category_pics = {
        'Random Thoughts': '',
        'Entertainment': 'https://images.unsplash.com/photo-1513346940221-6f673d962e97?ixlib=rb-4.0.3&'
                         'ixid=MnwxMjA3fDB8MHxwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=2070&q=80',
        'Technology': 'https://images.unsplash.com/photo-1526374965328-7f61d4dc18c5?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MH'
                      'xzZWFyY2h8MTV8fHRlY2h8ZW58MHwwfDB8fA%3D%3D&auto=format&fit=crop&w=800&q=60',
        'Education': 'https://images.unsplash.com/photo-1521587760476-6c12a4b040da?ixlib=rb-4.0.3&ixid=MnwxMjA3fDB8MH'
                     'xwaG90by1wYWdlfHx8fGVufDB8fHx8&auto=format&fit=crop&w=2070&q=80'
    }
    return render_template('post_category.html',
                           posts=posts,
                           category=category_name,
                           user=current_user,
                           filepath=category_pics[category_name])


if __name__ == '__main__':
    app.run(debug=True)


# TODO: Comments???
# TODO: Email validation: line 9 on wtforms.validators says to import email_validator, but it isn't working
