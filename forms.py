from flask_wtf import FlaskForm
from wtforms import StringField, SubmitField, PasswordField, SelectField, EmailField
from wtforms.validators import DataRequired, URL, Length, Email
from flask_ckeditor import CKEditorField


class CreatePostForm(FlaskForm):
    title = StringField("Blog Post Title", validators=[DataRequired()])
    subtitle = StringField("Subtitle", validators=[DataRequired()])
    genre = SelectField("Genre", validators=[DataRequired()],
                        choices=['Tech', 'Education', 'Entertainment', 'Random Thoughts'])
    img_url = StringField("Post Image URL", validators=[DataRequired(), URL()])
    body = CKEditorField("Post Content", validators=[DataRequired()])
    submit = SubmitField("Submit Post")


class RegisterForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password',
                             validators=[DataRequired(message='Please enter a password'),
                                         Length(min=7,
                                                max=25,
                                                message="Please choose a password between 7-25 characters")])
    submit = SubmitField('Sign up')


class LoginForm(FlaskForm):
    email = EmailField('Email', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login')


class CommentForm(FlaskForm):
    text = CKEditorField("Comment", validators=[DataRequired()])
    submit = SubmitField('Submit Comment')
