from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from app import app, db
from app.forms import (LoginForm, RegistrationForm, UserForm, ChangePasswordForm, DeleteUserForm,
                       VolunteerForm, SearchVolunteerForm)
from app.models import User, Volunteer


@app.route('/')
@app.route('/index')
def index():
    return render_template('index.html', title='Home')


@app.route('/login', methods=['GET', 'POST'])
def login():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = LoginForm()
    if form.validate_on_submit():
        user = User.query.filter_by(username=form.username.data).first()
        if user is None or not user.check_password(form.password.data):
            flash('Invalid username or password')
            return redirect(url_for('login'))
        login_user(user, remember=form.remember_me.data)
        next_page = request.args.get('next')
        if not next_page or url_parse(next_page).netloc != '':
            next_page = url_for('index')
        return redirect(next_page)
    return render_template('login.html', title='Sign In', form=form)


@app.route('/logout')
def logout():
    logout_user()
    return redirect(url_for('index'))


def create_user(first_name, last_name, username, password, email, phone):
    user = User(first_name=first_name, last_name=last_name, username=username, email=email, phone=phone)
    user.set_password(password)
    db.session.add(user)
    db.session.commit()
    return user.id


@app.route('/register', methods=['GET', 'POST'])
def register():
    if current_user.is_authenticated:
        return redirect(url_for('index'))
    form = RegistrationForm()
    if form.validate_on_submit():
        create_user(first_name=form.first_name.data, last_name=form.last_name.data,
                    username=form.username.data, password=form.password.data,
                    email=form.email.data, phone=form.phone.data)
        return redirect(url_for('login'))
    return render_template('register.html', title='Register', form=form)


@app.route('/view_users')
@login_required
def view_users():
    users = User.query.all()
    return render_template('view_users.html', title='Users', users=users)


@app.route('/view_user/<user_id>')
@login_required
def view_user(user_id):
    user = User.query.get(int(user_id))
    return render_template('view_user.html', title='User Dashboard', user=user)


@app.route('/add_user', methods=['GET', 'POST'])
@login_required
def add_user():
    form = RegistrationForm()
    if form.validate_on_submit():
        user_id = create_user(first_name=form.first_name.data, last_name=form.last_name.data,
                              username=form.username.data, password=form.password.data,
                              email=form.email.data, phone=form.phone.data)
        return redirect(url_for('view_user', user_id=user_id))
    return render_template('add_user.html', title='Add User', form=form)


@app.route('/edit_user/<user_id>', methods=['GET', 'POST'])
@login_required
def edit_user(user_id):
    user = User.query.get(int(user_id))
    form = UserForm()
    if form.validate_on_submit():
        user.first_name = form.first_name.data
        user.last_name = form.last_name.data
        user.email = form.email.data
        user.phone = form.phone.data
        db.session.add(user)
        db.session.commit()
        return redirect(url_for('view_user', user_id=user.id))
    form.first_name.data = user.first_name
    form.last_name.data = user.last_name
    form.email.data = user.email
    form.phone.data = user.phone
    return render_template('edit_user.html', title='Edit User', form=form)


@app.route('/change_password/<user_id>', methods=['GET', 'POST'])
@login_required
def change_password(user_id):
    user = User.query.get(int(user_id))
    form = ChangePasswordForm()
    if form.validate_on_submit():
        if user.check_password(form.old_password.data):
            user.set_password(form.password.data)
            db.session.add(user)
            db.session.commit()
            return redirect(url_for('view_user', user_id=user.id))
        else:
            flash('The password provided was not correct')
            return redirect(url_for('change_password', user_id=user.id))
    return render_template('change_password.html', title='Change Password', form=form)


@app.route('/delete_user/<user_id>', methods=['GET', 'POST'])
@login_required
def delete_user(user_id):
    user = User.query.get(int(user_id))
    form = DeleteUserForm()
    if form.validate_on_submit():
        if form.confirm.data:
            if current_user.id == user.id:
                logout_user()
            db.session.delete(user)
            db.session.commit()
            return redirect(url_for('index'))
        else:
            return redirect(url_for('index'))
    return render_template('delete_user.html', title='Delete User', form=form, user=user)


@app.route('/view_volunteers')
@login_required
def view_volunteers():
    volunteers = Volunteer.query.all()
    return render_template('view_volunteers.html', title='View Volunteers', volunteers=volunteers)


@app.route('/view_volunteer/<volunteer_id>')
@login_required
def view_volunteer(volunteer_id):
    volunteer = Volunteer.query.get(int(volunteer_id))
    return render_template('view_volunteer.html', title='View Volunteer', volunteer=volunteer)


@app.route('/add_volunteer', methods=['GET', 'POST'])
@login_required
def add_volunteer():
    form = VolunteerForm()
    if form.validate_on_submit():
        volunteer = Volunteer(first_name=form.first_name.data, last_name=form.last_name.data,
                              dob=form.dob.data, email=form.email.data, phone=form.phone.data,
                              address=form.address.data, city=form.city.data, state=form.state.data,
                              zip=form.zip.data)
        db.session.add(volunteer)
        db.session.commit()
        return redirect(url_for('view_volunteer', volunteer_id=volunteer.id))
    return render_template('add_volunteer.html', title='Add Volunteer', form=form)


@app.route('/edit_volunteer/<volunteer_id>', methods=['GET', 'POST'])
@login_required
def edit_volunteer(volunteer_id):
    volunteer = Volunteer.query.get(int(volunteer_id))
    form = VolunteerForm()
    if form.validate_on_submit():
        volunteer.first_name = form.first_name.data
        volunteer.last_name = form.last_name.data
        volunteer.dob = form.dob.data
        volunteer.email = form.email.data
        volunteer.phone = form.phone.data
        volunteer.address = form.address.data
        volunteer.city = form.city.data
        volunteer.state = form.state.data
        volunteer.zip = form.zip.data
        db.session.add(volunteer)
        db.session.commit()
        return redirect(url_for('view_volunteer', volunteer_id=volunteer.id))
    form.first_name.data = volunteer.first_name
    form.last_name.data = volunteer.last_name
    form.dob.data = volunteer.dob
    form.email.data = volunteer.email
    form.phone.data = volunteer.phone
    form.address.data = volunteer.address
    form.city.data = volunteer.city
    form.state.data = volunteer.state
    form.zip.data = volunteer.zip
    return render_template('edit_volunteer.html', title='Edit Volunteer', form=form)


@app.route('/delete_volunteer/<volunteer_id>')
@login_required
def delete_volunteer(volunteer_id):
    volunteer = Volunteer.query.get(int(volunteer_id))
    db.session.delete(volunteer)
    db.session.commit()
    return redirect(url_for('view_volunteers'))


@app.route('/search_volunteer', methods=['GET', 'POST'])
@login_required
def search_volunteer():
    form = SearchVolunteerForm()
    if form.validate_on_submit():
        name = form.name.data.split(' ')
        first_name, last_name = name[0], name[1]
        volunteer = Volunteer.query.filter_by(first_name=first_name, last_name=last_name).first()
        if volunteer is not None:
            return redirect(url_for('view_volunteer', volunteer_id=volunteer.id))
        flash('No volunteer found with that name')
        return redirect(url_for('search_volunteer'))
    return render_template('search_volunteer.html', title='Search Volunteer', form=form)

