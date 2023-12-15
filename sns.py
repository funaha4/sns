from flask import Flask, render_template, request, redirect, url_for, flash, session
from flask_sqlalchemy import SQLAlchemy
from werkzeug.security import generate_password_hash, check_password_hash
import uuid
from datetime import datetime
from flask_login import current_user, LoginManager, login_required

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:////tmp/test.db'
app.config['SECRET_KEY'] = 'secret'
db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)

class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    password = db.Column(db.String(120), nullable=False)

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    post_id = db.Column(db.Integer, db.ForeignKey('post.id'), nullable=False)

class Post(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    content = db.Column(db.Text, nullable=False)
    date_posted = db.Column(db.DateTime, nullable=False, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    uuid = db.Column(db.String(36), unique=True, nullable=False, default=str(uuid.uuid4()))
    replies = db.relationship('Reply', backref='post', lazy=True)
    user = db.relationship('User', backref='posts')
    
@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# This is the Flask route that handles the reply form submission
# @app.route('/post/<int:post_id>/reply', methods=['POST'])
# def create_reply(post_id):
#     if 'user.id' not in session:
#         flash('You must be logged in to reply to a post.')
#         return redirect(url_for('login'))

#     content = request.form['content']
#     user_id = session['user.id']
#     reply = Reply(content=content, user_id=user_id, post_id=post_id)
#     db.session.add(reply)
#     db.session.commit()
#     return redirect(url_for('index'))  # Or wherever you want to redirect the user after they create a reply

@app.route('/post/<int:post_id>/reply', methods=['GET', 'POST'])
def create_reply(post_id):
    if request.method == 'POST':
        content = request.form['content']
        reply = Reply(content=content, post_id=post_id, user_id=current_user.id)
        db.session.add(reply)
        db.session.commit()
        return redirect(url_for('view_post', post_id=post_id))
    # ここでGETリクエストを処理します

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        hashed_password = generate_password_hash(request.form['password'], method='pbkdf2:sha256')
        new_user = User(username=request.form['username'], password=hashed_password)
        db.session.add(new_user)
        db.session.commit()
        flash('Registration successful!')
        return redirect(url_for('login'))
    return render_template('register.html')

@app.route('/post/<int:post_id>')
def view_post(post_id):
    post = Post.query.get_or_404(post_id)
    replies = Reply.query.filter_by(post_id=post_id).all()
    return render_template('post.html', post=post, replies=replies)

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        user = User.query.filter_by(username=request.form['username']).first()
        if user and check_password_hash(user.password, request.form['password']):
            session['username'] = user.username
            flash('Login successful!')
            return redirect(url_for('index'))
        flash('Invalid username or password')
    return render_template('login.html')

from flask_login import login_required

@app.route('/post/<int:post_id>/reply', methods=['POST'])
@login_required
def reply_post(post_id):
    content = request.form['content']
    if current_user.is_authenticated:
        reply = Reply(content=content, post_id=post_id, user_id=current_user.id)
        db.session.add(reply)
        db.session.commit()
    return redirect(url_for('view_post', post_id=post_id))

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('index'))

@app.route('/index', methods=['GET', 'POST'])
def index():
    if request.method == 'POST':
        user = User.query.filter_by(username=session['username']).first()
        if user is None:
            flash('User not found')
            return redirect(url_for('login'))
        new_post = Post(content=request.form['content'], user_id=user.id, uuid=str(uuid.uuid4()))  # Generate UUID
        db.session.add(new_post)
        db.session.commit()
        flash('Post created')
        return redirect(url_for('index'))
    else:
        posts = Post.query.order_by(Post.date_posted.desc()).all()
        return render_template('index.html', posts=posts)

@app.route('/', methods=['GET', 'POST'])
def home():
    if request.method == 'POST':
        # Handle the POST request here
        return redirect(url_for('home'))  # Temporary redirect
    else:
        posts = Post.query.order_by(Post.date_posted.desc()).all()
        return render_template('index.html', posts=posts)


if __name__ == '__main__':
    with app.app_context():
        db.drop_all()
        db.create_all()  # This will create the database and the tables
    app.run(debug=True)