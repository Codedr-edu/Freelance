# Khai báo thư viện,framework,...
from flask import Flask, render_template, redirect, url_for, Blueprint, flash, Response, request
from flask_bootstrap import Bootstrap
from flask_wtf import FlaskForm
from wtforms import StringField, PasswordField, BooleanField, FileField, IntegerField, FloatField,TextAreaField,EmailField,RadioField,SubmitField
from wtforms.validators import InputRequired, Email, Length
from flask_sqlalchemy import *
from werkzeug.security import generate_password_hash, check_password_hash
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from datetime import datetime
import time
from datetime import datetime
from base64 import b64encode
import base64
from io import BytesIO
from werkzeug.utils import secure_filename
import os


db = SQLAlchemy()
app = Flask(__name__, template_folder='template',static_folder='static')
app.config['SECRET_KEY'] = 'investment-website'
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
views = Blueprint("views", __name__)
bootstrap = Bootstrap(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
db.init_app(app)

class User(UserMixin,db.Model):
    id = db.Column(db.Integer, primary_key = True)
    name = db.Column(db.String(15),nullable=False)
    email = db.Column(db.String(100),nullable=False)
    account_type = db.Column(db.Integer)
    balanced = db.Column(db.String())
    password = db.Column(db.String(80),nullable=False)
    def __repr__(self):
        return '<User {}>'.format(self.name)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

class Withdraw(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer,nullable=False)
    user_payment = db.Column(db.String(5),nullable=False)
    user_add = db.Column(db.String(),nullable=False)
    value = db.Column(db.String(),nullable=False)

class Deposit(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, nullable=False)
    user_payment = db.Column(db.String(5), nullable=False)
    user_add = db.Column(db.String(), nullable=False)
    value = db.Column(db.String(), nullable=False)

class Investplan(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    price = db.Column(db.String(), nullable=False)
    earnper = db.Column(db.String(), nullable=False)
    earnday = db.Column(db.String(), nullable=False)
    description = db.Column(db.String(),nullable=False)

class Referer(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer)
    refere_time = db.Column(db.Integer)
    address = db.Column(db.String())

@app.route('/login',methods=['GET','POST'])
def login():
    if request.method == "POST":
        email = request.form.get("email")
        password = request.form.get("password")

        user = User.query.filter_by(email=email).first()

        if not user or check_password_hash(user.password,password):
            return redirect(url_for('login'))
        else:
            login_user(user)
            return redirect(url_for('dashboard'))
    return render_template("login.html")


@app.route('/register',methods=['GET','POST'])
def register():
    if request.method == 'POST':
        name = request.form.get("name")
        email = request.form.get("email")
        type_cryp = request.form.get("type_cryp")
        password = request.form.get("password")

        pss = generate_password_hash(password,method='sha256')
        nws = User(name=name,email=email,account_type=1,type_cryp=type_cryp,password=pss,balanced=0)
        db.session.add(nws)
        db.session.commit()
        user = User.query.filter_by(email=email).first()
        login_user(user)
        return redirect(url_for('dashboard'))
    return render_template("register.html")


@login_required
@app.route('/dashboard')
def dashboard():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            return redirect(url_for('admin_dashboard'))
        referal_time = Referer.query.filter_by(user_id=current_user.id).first()
    else:
        return redirect(url_for('login'))
    return render_template("dashboard.html",referal=referal_time)

@login_required
@app.route('/investment/plan/view')
def investing_plan():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            return redirect(url_for('admin_dashboard'))
        else:
            opt = Investplan.query.all()
    else:
        return redirect(url_for('login'))
    return render_template("invest.html",posts=opt)

@login_required
@app.route('/withdraw/history')
def withdraw_history():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            return redirect(url_for('admin_dashboard'))
        else:
            wtd = Withdraw.query.filter_by(user_id=current_user.id).all()
    else:
        return redirect(url_for('login'))
    return render_template("withdraw_his.html",posts=wtd[::-1])

@login_required
@app.route('/deposit/history')
def deposit_history():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            return redirect(url_for('admin_dashboard'))
        else:
            wtd = Deposit.query.filter_by(user_id=current_user.id).all()
    else:
        return redirect(url_for('login'))
    return render_template("deposit_his.html",posts=wtd[::-1])

@login_required
@app.route('/withdraw/request',methods=['GET','POST'])
def withdraw_request():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            return redirect(url_for('admin_dashboard'))
        if request.method == "POST":
            value = request.form.get("value")
            payment_method = request.form.get("paymethod")
            payacc = request.form.get("Payacc")
            wtv = Withdraw(value=value,user_id=current_user.id,user_payment=payment_method,user_add=payacc)
            db.session.add(wtv)
            db.session.commit()
        #else:
            #return redirect(url_for('withdraw_request'))
    else:
        return redirect(url_for('dashboard'))
    return render_template('withdraw_req.html')

@login_required
@app.route('/deposit/request',methods=['GET','POST'])
def deposit_request():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            return redirect(url_for('admin_dashboard'))
        else:
            if request.method == "POST":
                value = request.form.get("value")
                payment_method = request.form.get("paymethod")
                payacc = request.form.get("payacc")
                if current_user.balanced <= value:
                    wtv = Deposit(value=value,user_id=current_user.id,user_payment=payment_method,user_add=payacc)
                    db.session.add(wtv)
                    db.session.commit()
                else:
                    return redirect(url_for('deposit_request'))
    else:
        return redirect(url_for('login'))
    return render_template('deposit_req.html')

@app.route('/<int:id>')
def referer_link(id):
    referer = Referer.query.filter_by(user_id=id).first()
    user = User.query.filter_by(id=id).first()
    if user:
        if referer:
            referer.refere_time += 1
            return redirect(url_for('index'))
        else:
            nrf = Referer(user_id=id,refere_time=1,address=user.address)
            db.session.add(nrf)
            db.session.commit()
            return redirect(url_for('index'))
    else:
        return redirect(url_for('index'))

@login_required
@app.route('/admin/dashboard')
def admin_dashboard():
    if current_user.is_authenticated:
        if current_user.account_type == 1:
            return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))
    return render_template("admin_dashboard.html")

@login_required
@app.route('/admin/deposit')
def admin_deposit():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            deposit = Deposit.query.all()
        else:
            return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))
    return render_template("admin_deposit.html",posts=deposit[::-1])

@login_required
@app.route('/admin/withdraw')
def admin_withdraw():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            withdraw = Withdraw.query.all()
        else:
            return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))
    return render_template("admin_withdraw.html",posts=withdraw[::-1])

@login_required
@app.route('/admin/referal')
def admin_referal():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            referal = Referer.query.all()
        else:
            return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))
    return render_template("admin_referal.html",posts=referal[::-1])

@login_required
@app.route('/referal/link')
def referal_link_make():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('login'))
    return render_template("referal_link.html")

@login_required
@app.route('/logout')
def log_out():
    if current_user.is_authenticated:
        logout_user()

@app.route('/admin/register',methods=['GET','POST'])
def admin_register():
    if request.method == 'POST':
        name = request.form.get("username")
        email = request.form.get("email")
        address = request.form.get("address")
        type_cryp = request.form.get("type_cryp")
        password = request.form.get("password")
        balanced = request.form.get("balanced")

        pss = generate_password_hash(password)
        nws = User(name=name, email=email, account_type=2, address=address,type_cryp=type_cryp,balanced=balanced, password=pss)
        db.session.add(nws)
        db.session.commit()
        user = User.query.filter_by(email=email).first()
        login_user(user)
        return redirect(url_for('admin_dashboard'))
    return render_template("admin_register.html")

@login_required
@app.route('/investment/plan/create',methods=['GET','POST'])
def investment_plan_create():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            if request.method == 'POST':
                price = request.form.get("price")
                earnper = request.form.get("percent")
                earnday = request.form.get("day")
                description = request.form.get("description")

                new = Investplan(price=int(price),earnday=int(earnday),earnper=int(earnper),description=description)
                db.session.add(new)
                db.session.commit()
                return redirect(url_for('admin_dashboard'))
        else:
            return redirect(url_for('dashboard'))
    else:
        return redirect(url_for('login'))
    return render_template('invest_create.html')

@app.route('/')
def index():
    return render_template("index.html")

@login_required
@app.route('/add/balanced',methods=['GET','POST'])
def add_balanced():
    if current_user.is_authenticated:
        if current_user.account_type == 1:
            return redirect(url_for('dashboard'))
        else:
            if request.method == 'POST':
                balanced = request.form.get('balanced')

                current_user.balanced += balanced
                db.session.commit()
                return redirect(url_for('admin_dashboard'))
    return render_template("add_balanced.html")

@login_required
@app.route('/withdraw/balanced',methods=['GET','POST'])
def withdraw_balanced():
    if current_user.is_authenticated:
        if current_user.account_type == 1:
            return redirect(url_for('dashboard'))
        else:
            if request.method == 'POST':
                balanced = request.form.get('balanced')
                user_id = request.form.get('user_id')
                user = User.query.filter_by(id=user_id)
                user.balanced -= balanced
                db.session.commit()
                return redirect(url_for('admin_dashboard'))
    return render_template("withdraw_balanced.html")

@login_required
@app.route('/deposit/balanced',methods=['GET','POST'])
def deposit_balanced():
    if current_user.is_authenticated:
        if current_user.account_type == 1:
            return redirect(url_for('dashboard'))
        else:
            if request.method == 'POST':
                balanced = request.form.get('balanced')
                user_id = request.form.get('user_id')
                user = User.query.filter_by(id=user_id)
                user.balanced += balanced
                db.session.commit()
                return redirect(url_for('admin_dashboard'))
    return render_template("deposit_balanced.html")

@login_required
@app.route('/payment/address')
def payment_address():
    if current_user.is_authenticated:
        if current_user.account_type == 2:
            return redirect(url_for('admin_dashboard'))
    else:
        return redirect(url_for('login'))
    return render_template('payment_address.html')


with app.app_context():
    db.create_all()

'''

if __name__ == '__main__':
    app.run(debug=True)
'''