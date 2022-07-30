from flask import render_template, flash, redirect, url_for, request
from flask_login import current_user, login_user, logout_user, login_required
from werkzeug.urls import url_parse
from app import app, db
from app.forms import (LoginForm, RegistrationForm, UserForm, ChangePasswordForm, DeleteUserForm)
from app.models import User


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
