from flask import Flask, render_template, redirect, url_for, flash, request
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, SubmitField, SelectField, TextAreaField
from wtforms.validators import DataRequired, Length, Email, EqualTo
from flask_bcrypt import Bcrypt
from twilio.rest import Client
from datetime import datetime
from phonenumbers import NumberParseException, PhoneNumberFormat
import phonenumbers
from flask_paginate import Pagination, get_page_parameter


app = Flask(__name__)
app.config['SECRET_KEY'] = 'your_secret_key'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///site.db'
db = SQLAlchemy(app)
login_manager = LoginManager(app)
login_manager.login_view = 'login'
bcrypt = Bcrypt(app)

# Twilio configuration
account_sid = "AC3a651c975f1b3729a28b763002a091fd"
auth_token = "b55df13f26b6a5f4e7d70d5dbf116e67"
client = Client(account_sid, auth_token)


class AdminLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login as Admin')

class OperatorLoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    submit = SubmitField('Login as Operator')

class User(db.Model, UserMixin):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(60), nullable=False)
    role = db.Column(db.String(20), nullable=False, default='operator')

    def set_password(self, password):
        self.password = bcrypt.generate_password_hash(password).decode('utf-8')

    def check_password(self, password):
        return bcrypt.check_password_hash(self.password, password)

class Contact(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    phone_number = db.Column(db.String(20), nullable=False)
    area_id = db.Column(db.Integer, db.ForeignKey('area.id'), nullable=False)

class Area(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    contacts = db.relationship('Contact', backref='area', lazy=True)

class CallLog(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    timestamp = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    status = db.Column(db.String(50), nullable=False)
    area_id = db.Column(db.Integer, db.ForeignKey('area.id'), nullable=False)

class Feedback(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    resident_id = db.Column(db.Integer, db.ForeignKey('contact.id'), nullable=False)
    message = db.Column(db.Text, nullable=False)

class Script(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    content = db.Column(db.Text, nullable=False)

class RegistrationForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired(), Length(min=6)])
    confirm_password = PasswordField('Confirm Password', validators=[DataRequired(), EqualTo('password')])
    submit = SubmitField('Sign Up')

class LoginForm(FlaskForm):
    email = StringField('Email', validators=[DataRequired(), Email()])
    password = PasswordField('Password', validators=[DataRequired()])
    user_type = SelectField('User Type', choices=[('admin', 'Admin'), ('operator', 'Operator')], validators=[DataRequired()])
    submit = SubmitField('Login')

class ContactForm(FlaskForm):
    name = StringField('Name', validators=[DataRequired()])
    phone_number = StringField('Phone Number', validators=[DataRequired()])
    area_id = SelectField('Area', coerce=int)
    submit = SubmitField('Add Contact')

class AreaForm(FlaskForm):
    name = StringField('Area Name', validators=[DataRequired()])
    submit = SubmitField('Add Area')

class FeedbackForm(FlaskForm):
    resident_id = SelectField('Resident', coerce=int)
    message = TextAreaField('Message', validators=[DataRequired()])
    submit = SubmitField('Submit Feedback')

class ScriptForm(FlaskForm):
    name = StringField('Script Name', validators=[DataRequired()])
    content = TextAreaField('Content', validators=[DataRequired()])
    submit = SubmitField('Save Script')

class CallForm(FlaskForm):
    area_id = SelectField('Area', coerce=int, validators=[DataRequired()])
    submit = SubmitField('Initiate Call')
class FeedbackForm(FlaskForm):
    resident_id = SelectField('Resident', coerce=int)
    message = TextAreaField('Feedback', validators=[DataRequired()])
    submit = SubmitField('Submit')
@app.route('/feedback', methods=['GET', 'POST'])
def feedback():
    form = FeedbackForm()
    form.resident_id.choices = [(contact.id, contact.name) for contact in Contact.query.all()]
    if form.validate_on_submit():
        feedback = Feedback(resident_id=form.resident_id.data, message=form.message.data)
        db.session.add(feedback)
        db.session.commit()
        flash('Feedback submitted successfully!', 'success')
        return redirect(url_for('feedback'))
    return render_template('feedback.html', form=form)
@app.route('/admin/feedback')
@login_required
def admin_feedback():
    feedbacks = Feedback.query.all()
    return render_template('admin_feedback.html', feedbacks=feedbacks)


@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

@app.route('/')
def home():
    return render_template('home.html')

@app.route('/admin_login', methods=['GET', 'POST'])
def admin_login():
    form = AdminLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, role='admin').first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('admin_dashboard'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
    return render_template('admin_login.html', form=form)

@app.route('/operator_login', methods=['GET', 'POST'])
def operator_login():
    form = OperatorLoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, role='operator').first()
        if user and user.check_password(form.password.data):
            login_user(user)
            return redirect(url_for('operator_dashboard'))
        else:
            flash('Login unsuccessful. Please check your email and password.', 'danger')
    return render_template('operator_login.html', form=form)

@app.route('/login', methods=['GET', 'POST'])
def login():
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(email=form.email.data, role=form.user_type.data).first()
        if user and user.check_password(form.password.data):
            login_user(user)
            if user.role == 'admin':
                return redirect(url_for('admin_dashboard'))
            else:
                return redirect(url_for('operator_dashboard'))
        else:
            flash('Login unsuccessful. Please check email and password.', 'danger')
    return render_template('login.html', form=form)

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('login'))

@app.route('/initiate_call', methods=['GET', 'POST'])
@login_required
def initiate_call():
    form = CallForm()
    form.area_id.choices = [(area.id, area.name) for area in Area.query.all()]

    if form.validate_on_submit():
        area_id = form.area_id.data
        message = "The water has been opened."
        residents = Contact.query.filter_by(area_id=area_id).all()
        for resident in residents:
            formatted_number = format_phone_number(resident.phone_number)
            if formatted_number:
                try:
                    call = client.calls.create(
                        to=formatted_number,
                        from_="+12244273694",  # Replace with your Twilio number
                        twiml=f'<Response><Say>{message}</Say></Response>'
                    )
                    print(f"Call SID: {call.sid}")
                    call_log = CallLog(status='initiated', area_id=area_id)
                    db.session.add(call_log)
                    db.session.commit()
                except Exception as e:
                    print(f"Failed to make call: {e}")
                    flash(f'Failed to make call to {formatted_number}.', 'danger')
            else:
                flash(f'Invalid phone number: {resident.phone_number}.', 'danger')
        flash('Calls initiated successfully!', 'success')
        return redirect(url_for('call_logs'))

    return render_template('initiate_call.html', form=form)

@app.route('/manage_contacts', methods=['GET', 'POST'])
@login_required
def manage_contacts():
    form = ContactForm()
    form.area_id.choices = [(area.id, area.name) for area in Area.query.all()]
    if form.validate_on_submit():
        contact = Contact(name=form.name.data, phone_number=format_phone_number(form.phone_number.data), area_id=form.area_id.data)
        db.session.add(contact)
        db.session.commit()
        flash('Contact added successfully!', 'success')
    contacts = Contact.query.all()
    return render_template('manage_contacts.html', form=form, contacts=contacts)


@app.route('/manage_areas', methods=['GET', 'POST'])
@login_required
def manage_areas():
    form = AreaForm()

    if form.validate_on_submit():
        # Check if the area already exists
        existing_area = Area.query.filter_by(name=form.name.data).first()
        if existing_area:
            flash('Area already exists!', 'danger')
        else:
            area = Area(name=form.name.data)
            db.session.add(area)
            db.session.commit()
            flash('Area added successfully!', 'success')
            return redirect(url_for('manage_areas'))

    # Pagination logic
    page = request.args.get(get_page_parameter(), type=int, default=1)
    per_page = 10  # Number of items per page
    areas_pagination = Area.query.paginate(page=page, per_page=per_page)
    pagination = Pagination(page=page, total=areas_pagination.total, per_page=per_page, css_framework='bootstrap4')

    return render_template('manage_areas.html', form=form, areas=areas_pagination.items, pagination=pagination)

@app.route('/delete_area/<int:area_id>', methods=['POST'])
@login_required
def delete_area(area_id):
    area = Area.query.get_or_404(area_id)
    db.session.delete(area)
    db.session.commit()
    flash('Area deleted successfully!', 'success')
    return redirect(url_for('manage_areas'))

@app.route('/report')
@login_required
def report():
    call_logs = CallLog.query.all()
    return render_template('report.html', call_logs=call_logs)

@app.route('/call_logs')
@login_required
def call_logs():
    call_logs = CallLog.query.all()
    areas = {area.id: area.name for area in Area.query.all()}
    return render_template('call_logs.html', call_logs=call_logs, areas=areas)

@app.route('/scripts', methods=['GET', 'POST'])
@login_required
def scripts():
    form = ScriptForm()
    if form.validate_on_submit():
        script = Script(name=form.name.data, content=form.content.data)
        db.session.add(script)
        db.session.commit()
        flash('Script saved successfully!', 'success')
        return redirect(url_for('scripts'))
    scripts = Script.query.all()
    return render_template('scripts.html', form=form, scripts=scripts)
@app.route('/test_call', methods=['GET'])
def test_call():
    try:
        call = client.calls.create(
            to='+1234567890',  # Replace with a valid phone number
            from_="YOUR_TWILIO_PHONE_NUMBER",  # Replace with your Twilio number
            twiml='<Response><Say>Hello from Twilio!</Say></Response>'
        )
        return f"Call initiated with SID: {call.sid}"
    except Exception as e:
        return f"Error: {e}"

@app.route('/manage_scripts', methods=['GET', 'POST'])
@login_required
def manage_scripts():
    form = ScriptForm()
    if form.validate_on_submit():
        script = Script(name=form.name.data, content=form.content.data)
        db.session.add(script)
        db.session.commit()
        flash('Script added successfully!', 'success')
    scripts = Script.query.all()
    return render_template('manage_scripts.html', form=form, scripts=scripts)


def format_phone_number(number):
    try:
        # Parse the number assuming it is from India
        parsed_number = phonenumbers.parse(number, "IN")

        # Check if the number is valid
        if not phonenumbers.is_valid_number(parsed_number):
            return None

        # Format the number in E.164 format
        formatted_number = phonenumbers.format_number(parsed_number, PhoneNumberFormat.E164)

        return formatted_number
    except NumberParseException:
        return None

def create_default_users():
    with app.app_context():
        admin = User.query.filter_by(email='admin@example.com').first()
        if not admin:
            admin = User(email='admin@example.com', role='admin')
            admin.set_password('admin_password')
            db.session.add(admin)

        operator = User.query.filter_by(email='operator@example.com').first()
        if not operator:
            operator = User(email='operator@example.com', role='operator')
            operator.set_password('operatorpassword')
            db.session.add(operator)

        db.session.commit()

@app.route('/dashboard')
@login_required
def dashboard():
    return render_template('dashboard.html')
@app.route('/operator_dashboard', endpoint='operator_dashboard')
def operator_dashboard():
    return render_template('operator_dashboard.html')
@app.route('/admin_dashboard', endpoint='admin_dashboard')
def admin_dashboard():
    return render_template('admin_dashboard.html')

if __name__ == '__main__':
    create_default_users()
    app.run(debug=True)
