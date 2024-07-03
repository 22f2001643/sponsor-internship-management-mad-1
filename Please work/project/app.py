from flask import Flask, render_template, redirect, url_for, flash, request, jsonify, send_from_directory, session
from functools import wraps
from forms import InfluencerRegistrationForm, SponsorRegistrationForm, LoginForm, AdminRegistrationForm
from werkzeug.security import generate_password_hash, check_password_hash
import sqlite3
import os
import secrets
from datetime import datetime


app = Flask(__name__, template_folder="templates", static_folder="static")
app.secret_key = os.urandom(24)

class Config:
    ROLE_CHOICES = [('admin', 'Admin'), ('influencer', 'Influencer'), ('sponsor', 'Sponsor')]

app.config.from_object(Config)

DATABASE = 'instance/users.db'

def get_db():
    conn = sqlite3.connect(DATABASE)
    conn.row_factory = sqlite3.Row
    return conn

def create_tables():
    db = get_db()
    cursor = db.cursor()
    cursor.execute('''CREATE TABLE IF NOT EXISTS user (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    username TEXT NOT NULL UNIQUE,
                    password TEXT NOT NULL,
                    role TEXT NOT NULL,
                    platform TEXT,
                    industry TEXT,
                    ratings INTEGER,
                    earnings REAL,
                    flag BOOLEAN
                  )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS campaign (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    sponsor_id INTEGER NOT NULL,
                    title TEXT NOT NULL,
                    description TEXT,
                    image_url TEXT,
                    niche TEXT,
                    start_date TEXT,
                    end_date TEXT,
                    budget REAL,
                    FOREIGN KEY(sponsor_id) REFERENCES user(id)
                  )''')

    cursor.execute('''CREATE TABLE IF NOT EXISTS influencer_request (
                    id INTEGER PRIMARY KEY AUTOINCREMENT,
                    influencer_id INTEGER NOT NULL,
                    campaign_id INTEGER NOT NULL,
                    status TEXT NOT NULL,
                    FOREIGN KEY(influencer_id) REFERENCES user(id),
                    FOREIGN KEY(campaign_id) REFERENCES campaign(id)
                  )''')

    cursor.execute('''
        CREATE TABLE IF NOT EXISTS influencer_campaign (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        influencer_id INTEGER,
        campaign_id INTEGER,
        status TEXT NOT NULL,
        FOREIGN KEY (influencer_id) REFERENCES user (id),
        FOREIGN KEY (campaign_id) REFERENCES campaign (id)
    )
''')

    
    db.commit()

db_initialized = False

@app.before_request
def initialize_db():
    global db_initialized
    if not db_initialized:
        create_tables()
        db_initialized = True

def login_required(f):
    @wraps(f)
    def decorated_function(*args, **kwargs):
        if 'username' not in session:
            flash('Please log in to access this page.', 'danger')
            return redirect(url_for('login'))
        return f(*args, **kwargs)
    return decorated_function

def role_required(role):
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            if session.get('role') != role:
                flash('Unauthorized access.', 'danger')
                return redirect(url_for('index'))
            return f(*args, **kwargs)
        return decorated_function
    return decorator

def generate_token(username):
    return secrets.token_urlsafe(32)

def validate_token(token):
    return bool(token)

def authenticate_user(username, password):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user WHERE username = ?', (username,))
    user = cursor.fetchone()
    if user and check_password_hash(user['password'], password):
        return generate_token(username)
    return None

@app.route('/')
def index():
    return render_template('index.html')

@app.route('/register_influencer', methods=['GET', 'POST'])
def register_influencer():
    form = InfluencerRegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        platform = form.platform.data
        
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('INSERT INTO user (username, password, role, platform) VALUES (?, ?, ?, ?)',
                           (username, password, 'influencer', platform))
            db.commit()
            flash('Influencer registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
        
        finally:
            cursor.close()
            db.close()
    
    return render_template('register_influencer.html', form=form)


@app.route('/register_sponsor', methods=['GET', 'POST'])
def register_sponsor():
    form = SponsorRegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        industry = form.industry.data
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('INSERT INTO user (username, password, role, industry) VALUES (?, ?, ?, ?)', (username, password, 'sponsor', industry))
            db.commit()
            flash('Sponsor registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
    return render_template('register_sponsor.html', form=form)

@app.route('/register_admin', methods=['GET', 'POST'])
def register_admin():
    form = AdminRegistrationForm()
    if form.validate_on_submit():
        username = form.username.data
        password = generate_password_hash(form.password.data)
        try:
            db = get_db()
            cursor = db.cursor()
            cursor.execute('INSERT INTO user (username, password, role) VALUES (?, ?, ?)', (username, password, 'admin'))
            db.commit()
            flash('Admin registration successful!', 'success')
            return redirect(url_for('login'))
        except sqlite3.IntegrityError:
            flash('Username already exists. Please choose a different one.', 'danger')
    return render_template('register_admin.html', form=form)
@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        role = request.form['role']
        
        db = get_db()
        cursor = db.cursor()
        cursor.execute('SELECT * FROM user WHERE username = ?', (username,))
        user = cursor.fetchone()

        if user:
            if user['flag'] == 1:
                flash('Your account has been flagged and you no longer have access.', 'danger')
            elif check_password_hash(user['password'], password):
                if user['role'] == role:
                    session['id'] = user['id']
                    session['username'] = user['username']
                    session['role'] = user['role']

                    if role == 'admin':
                        return redirect(url_for('admin_dashboard'))
                    elif role == 'sponsor':
                        return redirect(url_for('sponsor_dashboard'))
                    elif role == 'influencer':
                        return redirect(url_for('influencer_dashboard'))
                else:
                    flash('Incorrect role. Please select the correct role.', 'danger')
            else:
                flash('Incorrect username or password.', 'danger')
        else:
            flash('Incorrect username or password.', 'danger')

    return render_template('login.html')


@app.route('/admin_info')
@login_required
@role_required('admin')
def admin_info():
    db = get_db()
    cursor = db.cursor()

    # Fetching campaign details
    cursor.execute('SELECT * FROM campaign')
    campaigns = cursor.fetchall()

    # Fetching influencer details
    cursor.execute('SELECT * FROM user WHERE role = ?', ('influencer',))
    influencers = cursor.fetchall()

    return render_template('admin_base.html', campaigns=campaigns, influencers=influencers)


@app.route('/sponsor_dashboard')
@login_required
@role_required('sponsor')
def sponsor_dashboard():
    campaign_id = session.get('id')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM influencer_campaign WHERE campaign_id = ?', (campaign_id,))
    sent_requests = cursor.fetchall()
    sent_requests = [dict(row) for row in sent_requests]

    return render_template('sponsor_base.html', sent_requests=sent_requests)



@app.route('/sponsor_base')
@login_required
@role_required('sponsor')
def sponsor_base():
    sponsor_id = session.get('id')
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM campaign WHERE sponsor_id = ?', (sponsor_id,))
    campaigns = cursor.fetchall()

    # Ensure campaigns is a list of dictionaries
    campaigns = [dict(row) for row in campaigns]

    return render_template('sponsor_dashboard.html', campaigns=campaigns)

@app.route('/about')
def about():
    return render_template("about.html")

@app.route('/admin_dashboard')
@login_required
@role_required('admin')
def admin_dashboard():
    return render_template('admin_base.html')

@app.route('/influencer_dashboard')
@login_required
@role_required('influencer')
def influencer_dashboard():
    influencer_id = session.get('id')
    
    if not influencer_id:
        flash('Influencer ID not found in session.', 'danger')
        return redirect(url_for('login'))
    
    try:
        db = get_db()
        cursor = db.cursor()

        # Fetch sent requests
        cursor.execute('''
            SELECT c.id, c.title, c.description, c.start_date, c.end_date, c.budget, ic.status
            FROM influencer_campaign ic
            JOIN campaign c ON ic.campaign_id = c.id
            WHERE ic.influencer_id = ?
        ''', (influencer_id,))
        sent_requests = cursor.fetchall()
        sent_requests = [
            dict(
                id=row[0],
                title=row[1],
                description=row[2],
                start_date=row[3],
                end_date=row[4],
                budget=row[5],
                status=row[6]
            ) for row in sent_requests
        ]

        print("Sent Requests:", sent_requests)  # Debugging statement

    except Exception as e:
        print("An error occurred while fetching campaign data:", str(e))
        flash('An error occurred while fetching campaign data. Please try again later.', 'danger')
        return redirect(url_for('influencer_dashboard'))

    finally:
        cursor.close()
        db.close()

    return render_template('influencer_base.html', sent_requests=sent_requests)








@app.route('/update_campaign_status', methods=['POST'])
@login_required
@role_required('influencer')
def update_campaign_status():
    data = request.get_json()
    campaign_id = data.get('campaign_id')
    status = data.get('status')
    
    db = get_db()
    cursor = db.cursor()

    try:
        cursor.execute('''
            UPDATE influencer_request
            SET status = ?
            WHERE campaign_id = ? AND influencer_id = ?
        ''', (status, campaign_id, session.get('id')))
        db.commit()
        return jsonify({'success': True})
    except Exception as e:
        print(f"Error updating status: {e}")
        db.rollback()
        return jsonify({'success': False})




@app.route('/favicon.ico')
def favicon():
    return send_from_directory(os.path.join(app.root_path, 'static'),
                               'favicon.ico', mimetype='image/vnd.microsoft.icon')

@app.route('/add_campaign', methods=['GET','POST'])
@login_required
@role_required('sponsor')
def add_campaign():
    title = request.form['title']
    description = request.form['description']
    image_url = request.form['image_url']
    niche = request.form['niche']
    start_date = request.form['start_date']
    end_date = request.form['end_date']
    budget = request.form['budget']

    sponsor_id = session['id']  # Get the sponsor's user ID from the session

    db = get_db()
    cursor = db.cursor()
    cursor.execute('''
        INSERT INTO campaign (sponsor_id, title, description, image_url, niche, start_date, end_date, budget)
        VALUES (?, ?, ?, ?, ?, ?, ?, ?)
    ''', (sponsor_id, title, description, image_url, niche, start_date, end_date, budget))
    db.commit()

    flash('Campaign added successfully!', 'success')
    return redirect(url_for('sponsor_dashboard'))

@app.route('/edit_campaign/<int:campaign_id>', methods=['GET', 'POST'])
@login_required
@role_required('sponsor')
def edit_campaign(campaign_id):
    db = get_db()
    cursor = db.cursor()
    if request.method == 'POST':
        title = request.form['title']
        description = request.form['description']
        image_url = request.form['image_url']
        niche = request.form['niche']
        start_date = request.form['start_date']
        end_date = request.form['end_date']
        budget = request.form['budget']

        cursor.execute('''UPDATE campaign SET title = ?, description = ?, image_url = ?, niche = ?, start_date = ?, end_date = ?, budget = ?
                          WHERE id = ?''', (title, description, image_url, niche, start_date, end_date, budget, campaign_id))
        db.commit()
        flash('Campaign updated successfully.', 'success')
        return redirect(url_for('sponsor_profile'))

    cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
    campaign = cursor.fetchone()
    return render_template('edit_campaign.html', campaign=campaign)

@app.route('/delete_campaign/<int:campaign_id>', methods=['GET','POST'])
@login_required
@role_required('sponsor')
def delete_campaign(campaign_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('DELETE FROM campaign WHERE id = ?', (campaign_id,))
    db.commit()
    flash('Campaign deleted successfully.', 'success')
    return redirect(url_for('sponsor_profile'))

@app.route('/find')
@login_required  # Assuming login_required is defined elsewhere
def find():
    search_query = request.args.get('search', '')

    db = get_db()
    cursor = db.cursor()

    cursor.execute('SELECT * FROM campaign')
    campaigns = cursor.fetchall()

    if search_query:
        cursor.execute('SELECT id, username, platform, industry, flag FROM user WHERE role = ? AND (username LIKE ? OR platform LIKE ?)', ('influencer', '%' + search_query + '%', '%' + search_query + '%'))
    else:
        cursor.execute('SELECT id, username, platform, industry, flag FROM user WHERE role = ?', ('influencer',))
    influencers = cursor.fetchall()

    # Ensure each influencer has a 'flag' attribute
    for influencer in influencers:
        if influencer['flag'] is None:
            influencer['flag'] = False

    return render_template('find.html', campaigns=campaigns, influencers=influencers, search_query=search_query)

    db.close()

    return render_template('find.html', campaigns=campaigns, influencers=influencers)

@app.route('/find_admin', methods=['GET', 'POST'])
@login_required
def find_admin():
    search_query = request.args.get('search', '')

    db = get_db()
    cursor = db.cursor()

    # Fetch campaigns
    if search_query:
        cursor.execute('SELECT * FROM campaign WHERE title LIKE ?', ('%' + search_query + '%',))
    else:
        cursor.execute('SELECT * FROM campaign')
    campaigns = cursor.fetchall()

    # Fetch influencers
    if search_query:
        cursor.execute('SELECT id, username, platform, industry, flag FROM user WHERE role = ? AND (username LIKE ? OR platform LIKE ?)', ('influencer', '%' + search_query + '%', '%' + search_query + '%'))
    else:
        cursor.execute('SELECT id, username, platform, industry, flag FROM user WHERE role = ?', ('influencer',))
    influencers = cursor.fetchall()

    # Ensure each influencer has a 'flag' attribute
    for influencer in influencers:
        if influencer['flag'] is None:
            influencer['flag'] = False

    return render_template('find_admin.html', campaigns=campaigns, influencers=influencers, search_query=search_query)





@app.route('/profile_influencer')
@login_required  # Ensure the user is logged in
def profile_influencer():
    user_id=session['id']
    conn = sqlite3.connect('instance/users.db')
    cursor = conn.cursor()
    cursor.execute('SELECT username, platform, ratings, earnings FROM user WHERE id = ?', (user_id,))
    user = cursor.fetchone()
    conn.close()
    
    if user:
        return render_template("influencer_profile.html",user=user)

@app.route('/find_influencer')
@login_required  # Ensure the user is logged in
def find_influencer():
    search_query = request.args.get('search', '')

    db = get_db()
    cursor = db.cursor()

    # Fetch campaigns
    if search_query:
        cursor.execute('SELECT * FROM campaign WHERE title LIKE ?', ('%' + search_query + '%',))
    else:
        cursor.execute('SELECT * FROM campaign')
    campaigns = cursor.fetchall()

    # Fetch influencers
    cursor.execute('SELECT * FROM user WHERE role = ?', ('influencer',))
    influencers = cursor.fetchall()

    

    return render_template('find_influencer.html', campaigns=campaigns, influencers=influencers, search_query=search_query)




@app.route('/view_campaign/<int:campaign_id>')
@login_required
def view_campaign(campaign_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
    campaign = cursor.fetchone()

    if not campaign:
        flash('Campaign not found.', 'danger')
        return redirect(url_for('find'))

    return render_template('view_campaign.html', campaign=campaign)

@app.route('/view_campaign_for_influencer/<int:campaign_id>')
@login_required
def view_campaign_for_influencer(campaign_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
    campaign = cursor.fetchone()

    if not campaign:
        flash('Campaign not found.', 'danger')
        return redirect(url_for('find_influencer'))

    return render_template('view_campaign_for_influencer.html', campaign=campaign)

@app.route('/view_admin_influ/<int:influencer_id>')
@login_required
def view_admin_influ(influencer_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ?', (influencer_id,))
    influencer = cursor.fetchone()

    if not influencer:
        flash('Influencer not found.', 'danger')
        return redirect(url_for('find_admin'))

    return render_template('view_admin_influ.html', influencer=influencer)

@app.route('/view_admin_camp/<int:campaign_id>')
@login_required
def view_admin_camp(campaign_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
    campaign = cursor.fetchone()

    if not campaign:
        flash('Campaign not found.', 'danger')
        return redirect(url_for('find_admin'))

    return render_template('view_admin_camp.html', campaign=campaign)


@app.route('/view_campaign_profile/<int:campaign_id>')
@login_required
def view_campaign_profile(campaign_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
    campaign = cursor.fetchone()

    if not campaign:
        flash('Campaign not found.', 'danger')
        return redirect(url_for('sponsor_profile'))

    return render_template('view_campaign_profile.html', campaign=campaign)

@app.route('/view_influencer/<int:influencer_id>')
@login_required
def view_influencer(influencer_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM user WHERE id = ? AND role = ?', (influencer_id, 'influencer'))
    influencer = cursor.fetchone()

    if not influencer:
        flash('Influencer not found.', 'danger')
        return redirect(url_for('find'))

    return render_template('view_influencer.html', influencer=influencer)



@app.route('/sponsor_profile')
@login_required
@role_required('sponsor')
def sponsor_profile():
    sponsor_id = session.get('id')

    try:
        db = get_db()
        cursor = db.cursor()

        # Fetch campaigns created by the sponsor
        cursor.execute('SELECT * FROM campaign WHERE sponsor_id = ?', (sponsor_id,))
        campaigns = cursor.fetchall()
        campaigns = [dict(campaign) for campaign in campaigns]

        # Fetch requests received by the sponsor
        cursor.execute('''
            SELECT ir.id AS request_id, ir.status, c.title AS campaign_title, u.username AS influencer_username, u.id AS influencer_id
            FROM influencer_request ir
            JOIN campaign c ON ir.campaign_id = c.id
            JOIN user u ON ir.influencer_id = u.id
            WHERE c.sponsor_id = ?
        ''', (sponsor_id,))
        received_requests = cursor.fetchall()
        received_requests = [dict(request) for request in received_requests]

        # Fetch requests sent by the sponsor to influencers
        cursor.execute('''
            SELECT ic.id AS request_id, ic.status, c.title AS campaign_title, u.username AS influencer_username, u.id AS influencer_id
            FROM influencer_campaign ic
            JOIN campaign c ON ic.campaign_id = c.id
            JOIN user u ON ic.influencer_id = u.id
            WHERE c.sponsor_id = ?
        ''', (sponsor_id,))
        sent_requests = cursor.fetchall()
        sent_requests = [dict(request) for request in sent_requests]

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return "Error fetching dashboard data. Please try again later.", 500  # Return an error message with status code

    except Exception as e:
        print(f"Error: {e}")
        return "An unexpected error occurred.", 500  # Return an error message with status code

    finally:
        db.close()

    return render_template('sponsor_profile.html', campaigns=campaigns, received_requests=received_requests, sent_requests=sent_requests)


@app.route('/request_influencer/<int:influencer_id>', methods=['GET','POST'])
@login_required
def request_influencer(influencer_id):
    db = get_db()
    cursor = db.cursor()
    campaign_id = session.get('id')

    try:
        # Check if the influencer exists
        cursor.execute('SELECT * FROM user WHERE id = ? AND role = ?', (influencer_id,'influencer'))
        influencer = cursor.fetchone()
        if not influencer:
            flash({'message': 'Influencer not found.'}), 404
            return redirect(url_for('find'))

        # Check if request already exists
        cursor.execute('SELECT * FROM influencer_request WHERE campaign_id = ? AND influencer_id = ?', (campaign_id, influencer_id))
        existing_request = cursor.fetchone()
        if existing_request:
            flash({'message': 'Request already sent to this campaign.'}), 400
            return redirect(url_for('find'))

        # Insert new request
        cursor.execute('INSERT INTO influencer_request (campaign_id, influencer_id, status) VALUES (?, ?, ?)', (campaign_id, influencer_id, 'pending'))
        db.commit()
        flash({'message': 'Influencer request sent successfully!'}), 200
        return redirect(url_for('find'))

    except Exception as e:
        db.rollback()
        return jsonify({'message': f'Error requesting campaign: {str(e)}'}), 500

    finally:
        cursor.close()

    return redirect(url_for('find'))

@app.route('/request_campaign/<int:campaign_id>', methods=['POST'])
@login_required
def request_campaign(campaign_id):
    db = get_db()
    cursor = db.cursor()
    influencer_id = session.get('id')

    try:
        # Check if the campaign exists
        cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
        campaign = cursor.fetchone()
        if not campaign:
            return jsonify({'message': 'Campaign not found.'}), 404

        # Check if request already exists
        cursor.execute('SELECT * FROM influencer_campaign WHERE campaign_id = ? AND influencer_id = ?', (campaign_id, influencer_id))
        existing_request = cursor.fetchone()
        if existing_request:
            return jsonify({'message': 'Request already sent to this campaign.'}), 400

        # Insert new request
        cursor.execute('INSERT INTO influencer_campaign (campaign_id, influencer_id, status) VALUES (?, ?, ?)', (campaign_id, influencer_id, 'pending'))
        db.commit()
        return jsonify({'message': 'Campaign request sent successfully!'}), 200

    except Exception as e:
        db.rollback()
        return jsonify({'message': f'Error requesting campaign: {str(e)}'}), 500

    finally:
        cursor.close()

    return redirect(url_for('find_influencer'))




@app.route('/unrequest_campaign/<int:campaign_id>/<int:influencer_id>', methods=['GET','POST'])
@login_required
def unrequest_campaign(campaign_id, influencer_id):
    db = get_db()
    cursor = db.cursor()
    current_influencer_id = session.get('id')

    try:
        # Check if the campaign exists
        cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
        campaign = cursor.fetchone()
        if not campaign:
            return jsonify({'message': 'Campaign not found.'}), 404

        # Check if request exists for this campaign and influencer
        cursor.execute('SELECT * FROM influencer_campaign WHERE campaign_id = ? AND influencer_id = ?', (campaign_id, current_influencer_id))
        existing_request = cursor.fetchone()
        if not existing_request:
            return jsonify({'message': 'No request found for this campaign.'}), 404

        # Delete the request
        cursor.execute('DELETE FROM influencer_campaign WHERE campaign_id = ? AND influencer_id = ?', (campaign_id, influencer_id))
        db.commit()

        return jsonify({'message': 'Campaign request withdrawn successfully.'}), 200

    except sqlite3.Error as e:
        db.rollback()
        return jsonify({'status': 'error', 'message': 'Database error. Please try again later.'}), 500

    except Exception as e:
        return jsonify({'status': 'error', 'message': f'An unexpected error occurred: {str(e)}'}), 500

    finally:
        cursor.close()

@app.route('/campaign_request')
@login_required
@role_required('sponsor')
def campaign_request():
    try:
        db = get_db()
        cursor = db.cursor()

        sponsor_id = session.get('id')
        
        # Fetch all requests sent by this sponsor
        cursor.execute('''
            SELECT ir.id, u.username, u.platform, u.ratings, ir.status
            FROM influencer_request ir
            JOIN user u ON ir.influencer_id = u.id
            WHERE ir.campaign_id = ?
        ''', (sponsor_id,))
        requests = cursor.fetchall()

        db.close()

        return render_template('campaign_request.html', requests=requests)

    except Exception as e:
        print(f"Error fetching requests sent by sponsor: {e}")
        flash("Error fetching requests sent by sponsor. Please try again later.", 'error')
        return redirect(url_for('campaign_request'))

@app.route('/requests_to_influencer')
@login_required
@role_required('influencer')
def requests_to_influencer():
    try:
        influencer_id = session.get('id')
        
        if not influencer_id:
            flash('Influencer ID not found in session.', 'danger')
            return redirect(url_for('login'))
        
        db = get_db()
        db.row_factory = sqlite3.Row  # This allows us to access rows as dictionaries
        cursor = db.cursor()

        # Fetch requests sent to influencers
        cursor.execute('''
            SELECT c.id, c.title, c.start_date, c.end_date, c.budget, ic.status, ic.campaign_id
            FROM influencer_request ic
            JOIN campaign c ON ic.campaign_id = c.sponsor_id
            WHERE ic.influencer_id = ?
        ''', (influencer_id,))
        sent_requests = cursor.fetchall()
        sent_requests = [dict(request) for request in sent_requests]

    except Exception as e:
        print(f"Error fetching requests: {e}")
        flash('Error fetching requests. Please try again later.', 'danger')
        return redirect(url_for('requests_to_influencer'))
    
    finally:
        if cursor:
            cursor.close()
        if db:
            db.close()

    return render_template('requests_to_influencer.html', sent_requests=sent_requests,influencer_id=influencer_id)








@app.route('/accept_request/<int:request_id>/<int:influencer_id>', methods=['POST'])
@login_required
@role_required('influencer')
def accept_request(request_id, influencer_id):
    # influencer_id = session.get('id')  # Get the influencer's user ID from the session

    if not influencer_id:
        # Handle the case where the session does not contain the influencer ID
        flash('Influencer ID not found in session.', 'danger')
        return redirect(url_for('login'))

    try:
        db = get_db()
        cursor = db.cursor()

        # Update the status of the request to 'accepted'
        cursor.execute('UPDATE influencer_request SET status = ? WHERE campaign_id = ? AND influencer_id = ?', ('accepted', request_id, influencer_id))
        db.commit()  # Commit the transaction

        flash('Request accepted successfully!', 'success')

    except Exception as e:
        # Handle any errors that occur during the database operations
        print("An error occurred while accepting the request:", str(e))
        flash('An error occurred while accepting the request. Please try again later.', 'danger')

    finally:
        # Ensure the database connection is closed
        cursor.close()
        db.close()

    return redirect(url_for('requests_to_influencer'))



@app.route('/reject_request/<int:request_id>', methods=['POST'])
@login_required
@role_required('influencer')
def reject_request(request_id):
    influencer_id = session.get('id')  # Get the influencer's user ID from the session

    if not influencer_id:
        # Handle the case where the session does not contain the influencer ID
        flash('Influencer ID not found in session.', 'danger')
        return redirect(url_for('login'))

    try:
        db = get_db()
        cursor = db.cursor()

        # Update the status of the request to 'accepted'
        cursor.execute('UPDATE influencer_request SET status = ? WHERE campaign_id = ? AND influencer_id = ?', ('rejected', request_id, influencer_id))
        db.commit()

        flash('Request rejected successfully!', 'success')

    except Exception as e:
        # Handle any errors that occur during the database operations
        print("An error occurred while accepting the request:", str(e))
        flash('An error occurred while accepting the request. Please try again later.', 'danger')

    finally:
        # Ensure the database connection is closed
        cursor.close()
        db.close()

    return redirect(url_for('influencer_dashboard'))

@app.route('/rating_earning/<int:campaign_id>')
@login_required
@role_required('influencer')
def rating_earning(campaign_id):
    try:
        db = get_db()
        cursor = db.cursor()

        # Fetch campaign details
        cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
        campaign = cursor.fetchone()

        if not campaign:
            flash("Campaign not found.")
            return redirect(url_for('influencer_dashboard'))

        # Fetch sponsor details
        cursor.execute('SELECT * FROM user WHERE id = ?', (campaign['sponsor_id'],))
        sponsor = cursor.fetchone()

        if not sponsor:
            flash("Sponsor not found.")
            return redirect(url_for('influencer_dashboard'))

        # Fetch influencers associated with the campaign
        cursor.execute('SELECT * FROM user WHERE id IN (SELECT influencer_id FROM influencer_request WHERE campaign_id = ?)', (campaign_id,))
        influencers = cursor.fetchall()

        db.close()

        return render_template('rating_earning.html', campaign=campaign, influencers=influencers, sponsor=sponsor)

    except Exception as e:
        print(f"Error loading rating and earning details: {e}")
        return "Error loading rating and earning details. Please try again later.", 500

@app.route('/rating_paying/<int:influencer_id>', methods=['GET', 'POST'])
@login_required
@role_required('sponsor')
def rating_paying(influencer_id):
    if request.method == 'GET':
        try:
            db = get_db()
            cursor = db.cursor()

            # Fetch influencer details
            cursor.execute('SELECT * FROM user WHERE id = ?', (influencer_id,))
            influencer = cursor.fetchone()

            # Fetch campaign details (if needed)
            # Replace with your campaign retrieval logic
            # For example, fetching campaign related to this sponsor
            sponsor_id = session.get('id')
            cursor.execute('SELECT * FROM campaign WHERE sponsor_id = ?', (sponsor_id,))
            campaign = cursor.fetchone()

            db.close()

            return render_template('rating_paying.html', campaign=campaign, influencer=influencer)

        except Exception as e:
            print(f"Error loading rating and paying details: {e}")
            flash("Error loading rating and paying details. Please try again later.", 'error')
            return redirect(url_for('sponsor_profile'))

    elif request.method == 'POST':
        try:
            # Handle form submission for ratings and payment
            influencer_id = request.form.get('influencer_id')
            rating = request.form.get('rating')
            budget = request.form.get('budget')

            # Calculate payment amount
            payment_amount = float(rating) * float(budget) / 5.0

            # Update influencer ratings in the database
            db = get_db()
            cursor = db.cursor()
            cursor.execute('UPDATE user SET ratings = ? WHERE id = ?', (rating, influencer_id))

            # Update earnings in the user table
            cursor.execute('SELECT earnings FROM user WHERE id = ?', (influencer_id,))
            current_earnings = cursor.fetchone()[0]  # Fetch the current earnings
            new_earnings = current_earnings + payment_amount
            cursor.execute('UPDATE user SET earnings = ? WHERE id = ?', (new_earnings, influencer_id))

            db.commit()
            db.close()

            flash(f"Successfully rated and paid influencer {influencer_id}.", 'success')
            return redirect(url_for('sponsor_profile'))

        except Exception as e:
            print(f"Error rating and paying influencer: {e}")
            flash("Error rating and paying influencer. Please try again later.", 'error')
            return redirect(url_for('sponsor_profile'))

    return render_template('rating_paying.html')




@app.route('/accept_influencer/<int:request_id>', methods=['POST'])
@login_required
@role_required('sponsor')
def accept_influencer(request_id):
    sponsor_id = session.get('id')  # Get the sponsor's user ID from the session

    if not sponsor_id:
        flash('Sponsor ID not found in session.', 'danger')
        return redirect(url_for('login'))

    try:
        db = get_db()
        cursor = db.cursor()

        # Fetch the campaign_id associated with the request_id
        cursor.execute('SELECT campaign_id FROM influencer_campaign WHERE id = ?', (request_id,))
        result = cursor.fetchone()
        if result:
            campaign_id = result[0]

            # Check if the campaign_id matches the sponsor_id in the campaign table
            cursor.execute('SELECT sponsor_id FROM campaign WHERE id = ?', (campaign_id,))
            result = cursor.fetchone()
            if result and result[0] == sponsor_id:
                # Update the status of the request to 'accepted'
                cursor.execute('UPDATE influencer_campaign SET status = ? WHERE id = ?', ('accepted', request_id))
                db.commit()

                flash('Request accepted successfully!', 'success')
            else:
                flash('Unauthorized to accept this request.', 'danger')
        else:
            flash('Request not found.', 'danger')

    except Exception as e:
        # Print detailed error message for debugging
        print(f"Error accepting request: {str(e)}")
        flash('An error occurred while accepting the request. Please try again later.', 'danger')

    finally:
        cursor.close()
        db.close()

    return redirect(url_for('sponsor_profile'))




@app.route('/reject_influencer/<int:request_id>', methods=['GET','POST'])
@login_required
@role_required('sponsor')
def reject_influencer(request_id):
    campaign_id = session.get('id')  # Get the influencer's user ID from the session

    if not campaign_id:
        # Handle the case where the session does not contain the influencer ID
        flash('Campaign ID not found in session.', 'danger')
        return redirect(url_for('login'))

    try:
        db = get_db()
        cursor = db.cursor()

        # Update the status of the request to 'accepted'
        cursor.execute('UPDATE influencer_campaign SET status = ? WHERE id = ? AND campaign_id = ?', ('rejected', request_id, campaign_id))
        db.commit()

        flash('Request rejected successfully!', 'success')
        return redirect(url_for('sponsor_profile'))

    except Exception as e:
        # Handle any errors that occur during the database operations
        print("An error occurred while accepting the request:", str(e))
        flash('An error occurred while accepting the request. Please try again later.', 'danger')

    finally:
        # Ensure the database connection is closed
        cursor.close()
        db.close()

    return redirect(url_for('sponsor_profile'))


@app.route('/submit_rating/<int:user_id>', methods=['POST'])
@login_required
@role_required('sponsor')
def submit_rating(user_id):
    try:
        rating = int(request.form['rating'])

        # Logic to update the rating in the database
        db = get_db()
        cursor = db.cursor()
        
        cursor.execute('UPDATE user SET ratings = ? WHERE id = ?', (rating, user_id))
        db.commit()

        db.close()

        return "Rating submitted successfully."
    except Exception as e:
        print(f"Error submitting rating: {e}")
        return "Error submitting rating. Please try again later.", 500
    
@app.route('/submit_rating_sp', methods=['POST'])
@login_required
@role_required('influencer')
def submit_rating_sp():
    influencer_id = session.get('id')
    sponsor_id = request.form.get('sponsor_id')
    rating = int(request.form.get('rating'))
    campaign_id = request.form.get('campaign_id')  # Ensure this value is available in the form

    try:
        db = get_db()
        cursor = db.cursor()

        # Fetch current ratings and count of ratings
        cursor.execute('SELECT ratings, COUNT(*) FROM user WHERE id = ? AND role = "sponsor"', (sponsor_id,))
        result = cursor.fetchone()
        
        if result is None:
            flash("Sponsor not found.")
            return redirect(url_for('stats_influencer'))  # Adjust the redirect target as needed

        current_rating, count = result

        # If the sponsor has no ratings yet, set the initial rating
        if current_rating is None:
            new_rating = rating
        else:
            # Calculate new average rating
            new_rating = (current_rating * count + rating) / (count + 1)

        # Update the sponsor's rating
        cursor.execute('UPDATE user SET ratings = ? WHERE id = ? AND role = "sponsor"', (new_rating, sponsor_id))
        db.commit()
        db.close()

        flash("Rating submitted successfully.")
        return redirect(url_for('rating_earning', campaign_id=campaign_id))  # Pass the campaign_id here
    
    except Exception as e:
        print(f"Error submitting rating: {e}")
        return "Error submitting rating. Please try again later.", 500





@app.route('/flag_campaign/<int:campaign_id>', methods=['POST'])
def flag_campaign(campaign_id):
    data = request.get_json()
    flag = data.get('flag', False)
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE campaign SET flag = ? WHERE id = ?', (flag, campaign_id))
    db.commit()
    db.close()

    return jsonify({'message': 'Campaign flagged successfully.'})

@app.route('/flag_influencer/<int:influencer_id>', methods=['POST'])
def flag_influencer(influencer_id):
    data = request.get_json()
    flag = data.get('flag', False)
    
    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE user SET flag = ? WHERE id = ?', (flag, influencer_id))
    db.commit()
    db.close()

    return jsonify({'message': 'Influencer flagged successfully.'})

@app.route('/unflag_campaign/<int:campaign_id>', methods=['POST'])
def unflag_campaign(campaign_id):
    # Get flag status from request data (if needed)
    data = request.get_json()
    flag = data.get('flag', False)  # Ensure you handle this appropriately in the frontend if needed

    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE campaign SET flag = ? WHERE id = ?', (flag, campaign_id))
    db.commit()
    db.close()

    return jsonify({'message': 'Campaign unflagged successfully.'})

@app.route('/unflag_influencer/<int:influencer_id>', methods=['POST'])
def unflag_influencer(influencer_id):
    # Get flag status from request data (if needed)
    data = request.get_json()
    flag = data.get('flag', False)  # Ensure you handle this appropriately in the frontend if needed

    db = get_db()
    cursor = db.cursor()
    cursor.execute('UPDATE user SET flag = ? WHERE id = ?', (flag, influencer_id))
    db.commit()
    db.close()

    return jsonify({'message': 'Influencer unflagged successfully.'})





@app.route('/get_campaign/<int:campaign_id>')
@login_required
@role_required('sponsor')
def get_campaign(campaign_id):
    db = get_db()
    cursor = db.cursor()
    cursor.execute('SELECT * FROM campaign WHERE id = ?', (campaign_id,))
    campaign = cursor.fetchone()
    if campaign:
        return jsonify({'success': True, 'campaign': dict(campaign)})
    else:
        return jsonify({'success': False}), 404

@app.route('/influencer_profile')
@login_required
@role_required('influencer')
def influencer_profile():
    influencer_id = session.get('id')  # Get the influencer's user ID from the session

    db = get_db()
    cursor = db.cursor()

    # Fetch influencer details
    cursor.execute('SELECT username, ratings, earnings FROM user WHERE id = ?', (influencer_id,))
    influencer = cursor.fetchone()

    if not influencer:
        flash('Influencer not found.', 'danger')
        return redirect(url_for('index'))

    # Render influencer dashboard template with influencer details
    return render_template('influencer_profile.html', influencer=influencer)

@app.route('/view_requests')
@login_required
@role_required('sponsor')
def view_requests():
    sponsor_id = session.get('id')

    db = get_db()
    cursor = db.cursor()

    # Fetch all influencer requests for the sponsor
    cursor.execute('''
        SELECT ir.id, u.username AS influencer_username, u.platform AS influencer_platform, u.ratings AS influencer_ratings, c.title AS campaign_title, ir.status
        FROM influencer_request ir
        JOIN user u ON ir.influencer_id = u.id
        JOIN campaign c ON ir.campaign_id = c.id
        WHERE c.sponsor_id = ? 
    ''', (sponsor_id,))
    
    requests = cursor.fetchall()

    return render_template('view_request.html', requests=requests)


@app.route('/withdraw_request/<int:request_id>', methods=['POST'])
@login_required
@role_required('influencer')
def withdraw_request(request_id):
    try:
        db = get_db()
        cursor = db.cursor()
        influencer_id = session.get('id')

        # Check if the request exists and belongs to the current user (influencer)
        cursor.execute('''
            SELECT ir.campaign_id 
            FROM influencer_campaign ir
            WHERE ir.campaign_id = ? AND ir.influencer_id = ?
        ''', (request_id, influencer_id))
        request_entry = cursor.fetchone()
        if not request_entry:
            return jsonify({'status': 'error', 'message': 'Request not found or unauthorized.'}), 404

        # Delete the request with the given ID
        cursor.execute('DELETE FROM influencer_campaign WHERE campaign_id = ?', (request_id,))
        db.commit()

        flash({'status': 'success', 'message': 'Campaign request withdrawn successfully.'}), 200
        return redirect(url_for('influencer_dashboard'))

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return jsonify({'status': 'error', 'message': 'Database error. Please try again later.'}), 500
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred.'}), 500
    finally:
        db.close()


@app.route('/withdraw_influencer/<int:request_id>', methods=['POST'])
@login_required
@role_required('sponsor')
def withdraw_influencer(request_id):
    try:
        db = get_db()
        cursor = db.cursor()
        campaign_id = session.get('id')

        # Check if the request exists and belongs to the current user (influencer)
        cursor.execute('''
            SELECT ir.id 
            FROM influencer_request ir
            WHERE ir.id = ? AND ir.campaign_id = ?
        ''', (request_id, campaign_id))
        request_entry = cursor.fetchone()
        if not request_entry:
            flash({'status': 'error', 'message': 'Request not found or unauthorized.'}), 404
            return redirect(url_for('campaign_request'))

        # Delete the request with the given ID
        cursor.execute('DELETE FROM influencer_request WHERE id = ?', (request_id,))
        db.commit()

        flash({'status': 'success', 'message': 'Influencer request withdrawn successfully.'}), 200
        return redirect(url_for('campaign_request'))

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return jsonify({'status': 'error', 'message': 'Database error. Please try again later.'}), 500
    except Exception as e:
        print(f"Error: {e}")
        return jsonify({'status': 'error', 'message': 'An unexpected error occurred.'}), 500
    finally:
        db.close()

@app.route('/stats')
def stats():
    db = get_db()
    cursor = db.cursor()

    # Count influencers
    cursor.execute('SELECT COUNT(*) FROM user WHERE role = ?', ('influencer',))
    num_influencers = cursor.fetchone()[0]

    # Count sponsors
    cursor.execute('SELECT COUNT(*) FROM user WHERE role = ?', ('sponsor',))
    num_sponsors = cursor.fetchone()[0]

    return render_template('stats_admin.html', num_influencers=num_influencers, num_sponsors=num_sponsors)


@app.route('/sponsors', methods=['GET'])
@login_required
def get_sponsors():
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT id, username FROM user WHERE role = ?', ('sponsor',))
    sponsors = cursor.fetchall()
    
    db.close()
    
    return jsonify({'sponsors': [dict(row) for row in sponsors]})

# Route to fetch campaigns for a specific sponsor
@app.route('/sponsor_campaigns/<int:sponsor_id>', methods=['GET'])
@login_required
def get_sponsor_campaigns(sponsor_id):
    db = get_db()
    cursor = db.cursor()
    
    cursor.execute('SELECT title, budget FROM campaign WHERE sponsor_id = ?', (sponsor_id,))
    campaigns = cursor.fetchall()
    
    db.close()
    
    return jsonify({'campaigns': [dict(row) for row in campaigns]})



@app.route('/ratings', methods=['GET'])
@login_required
def get_ratings():
    db = get_db()
    cursor = db.cursor()

    cursor.execute('SELECT u.username AS influencer_username, u.ratings AS influencer_ratings FROM user u WHERE u.role != ?', ('admin',))
    ratings = cursor.fetchall()

    db.close()

    ratings_list = [{'influencer_username': row['influencer_username'], 'influencer_ratings': row['influencer_ratings']} for row in ratings]

    return jsonify({'ratings': ratings_list})

@app.route('/stats_sponsor')
@login_required
def stats_sponsor():
    try:
        db = get_db()
        cursor = db.cursor()

        # Count influencers by platform
        cursor.execute('SELECT platform, COUNT(*) AS count FROM user WHERE role = ? GROUP BY platform', ('influencer',))
        platform_stats = cursor.fetchall()

        # Calculate average ratings of influencers
        cursor.execute('SELECT AVG(ratings) AS avg_ratings FROM user WHERE role = ? AND ratings IS NOT NULL', ('influencer',))
        avg_ratings = cursor.fetchone()['avg_ratings']

        # Ratings vs. Influencers
        cursor.execute('''
            SELECT u.username as influencer_name, u.ratings
            FROM user u
            WHERE u.role = ? AND u.ratings IS NOT NULL
        ''', ('influencer',))
        ratings_vs_influencers = cursor.fetchall() or []

        db.close()

        return render_template('stats_sponsor.html', platform_stats=platform_stats, avg_ratings=avg_ratings, ratings_vs_influencers=ratings_vs_influencers)

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return "Error fetching statistics. Please try again later.", 500  # Return an error message with status code

    except Exception as e:
        print(f"Error: {e}")
        return "An unexpected error occurred.", 500


    
@app.route('/about_main')
def about_main():
    return render_template("about_main.html")


@app.route('/stats_influencer')
@login_required
def stats_influencer():
    try:
        db = get_db()
        cursor = db.cursor()

        # Set row factory to fetch rows as dictionaries
        cursor.row_factory = sqlite3.Row

        # Fetch data for campaigns vs budget
        cursor.execute('''
            SELECT c.title AS campaign_title, c.budget
            FROM campaign c
            WHERE c.sponsor_id IS NOT NULL
        ''')
        campaigns_vs_budget = cursor.fetchall()

        # Fetch data for sponsor vs count of campaigns
        cursor.execute('''
            SELECT u.username AS sponsor_name, COUNT(c.id) AS campaign_count
            FROM user u
            LEFT JOIN campaign c ON u.id = c.sponsor_id
            WHERE u.role = 'sponsor'
            GROUP BY u.username
        ''')
        sponsor_vs_campaign_count = cursor.fetchall()

        # Fetch data for sponsor vs ratings
        cursor.execute('''
            SELECT u.username AS sponsor_name, AVG(u.ratings) AS avg_ratings
            FROM user u
            WHERE u.role = 'sponsor' AND u.ratings IS NOT NULL
            GROUP BY u.username
        ''')
        sponsor_vs_ratings = cursor.fetchall()

        db.close()

        # Convert rows to dictionaries for JSON serialization
        campaigns_vs_budget = [dict(row) for row in campaigns_vs_budget]
        sponsor_vs_campaign_count = [dict(row) for row in sponsor_vs_campaign_count]
        sponsor_vs_ratings = [dict(row) for row in sponsor_vs_ratings]

        # Render template with JSON-serializable data
        return render_template('stats_influencer.html', campaigns_vs_budget=campaigns_vs_budget, sponsor_vs_campaign_count=sponsor_vs_campaign_count, sponsor_vs_ratings=sponsor_vs_ratings)

    except sqlite3.Error as e:
        print(f"SQLite error: {e}")
        return "Error fetching statistics. Please try again later.", 500  # Return an error message with status code

    except Exception as e:
        print(f"Error: {e}")
        return "An unexpected error occurred.", 500







@app.route('/get_influencer_stats')
@login_required
@role_required('sponsor')
def get_influencer_stats():
    db = get_db()
    cursor = db.cursor()

    cursor.execute('SELECT COUNT(id) AS num_influencers FROM user WHERE role = "influencer"')
    num_influencers = cursor.fetchone()['num_influencers']

    cursor.execute('SELECT AVG(ratings) AS avg_ratings, AVG(earnings) AS avg_earnings FROM user WHERE role = "influencer"')
    stats = cursor.fetchone()

    return jsonify({
        'num_influencers': num_influencers,
        'avg_ratings': stats['avg_ratings'],
        'avg_earnings': stats['avg_earnings']
    })

@app.route('/get_campaign_data')
@login_required
@role_required('influencer')
def get_campaign_data():
    db = get_db()
    cursor = db.cursor()

    cursor.execute('''
        SELECT c.id, c.title, c.description, c.image_url, c.niche, c.start_date, c.end_date, c.budget, u.username as sponsor_username
        FROM campaign c
        JOIN user u ON c.sponsor_id = u.id
    ''')

    campaigns = cursor.fetchall()

    # Convert rows to dictionaries
    campaigns = [dict(campaign) for campaign in campaigns]

    return jsonify(campaigns)






@app.route('/logout', methods=['GET','POST'])
def logout():
    session.clear()
    flash('Logout successful', 'success')
    return redirect(url_for('login'))

if __name__ == '__main__':
    app.run(debug=True, host="0.0.0.0", port=6480)


##unflag dropdown stats sent request
