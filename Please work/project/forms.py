from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, RadioField
from wtforms.validators import DataRequired, Length, EqualTo

class InfluencerRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=20)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    platform = RadioField('Social Media Platform', choices=[('Instagram', 'Instagram'),
        ('YouTube', 'YouTube'),
        ('TikTok', 'TikTok'),
        ('Twitter', 'Twitter')
        # Add more choices as needed
    ], validators=[DataRequired()])
    submit = SubmitField('Register')


class SponsorRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    industry = StringField('Industry', validators=[DataRequired(), Length(min=2, max=150)])
    submit = SubmitField('Register')

class LoginForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired()])
    password = PasswordField('Password', validators=[DataRequired()])
    role = RadioField('Login as', choices=[('admin', 'Admin'), ('influencer', 'Influencer'), ('sponsor', 'Sponsor')], validators=[DataRequired()])
    submit = SubmitField('Login')

class AdminRegistrationForm(FlaskForm):
    username = StringField('Username', validators=[DataRequired(), Length(min=2, max=150)])
    password = PasswordField('Password', validators=[DataRequired()])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Register')
