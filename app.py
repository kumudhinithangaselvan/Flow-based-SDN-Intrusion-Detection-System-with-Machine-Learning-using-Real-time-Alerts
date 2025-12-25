from flask import Flask, render_template, request, redirect, url_for, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from werkzeug.security import generate_password_hash, check_password_hash
import pandas as pd
import numpy as np
import pickle
import os
import uuid
from datetime import datetime
import json
import matplotlib
matplotlib.use('Agg')
import matplotlib.pyplot as plt
import seaborn as sns
import io
import base64

# Initialize Flask app
app = Flask(__name__)
app.secret_key = 'sdn_intrusion_detection_secret_key'

# Configure database
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///database.db'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
app.config['UPLOAD_FOLDER'] = 'uploads'

# Initialize database
db = SQLAlchemy(app)

# Initialize login manager
login_manager = LoginManager(app)
login_manager.login_view = 'index'

# Load the trained models
def load_models():
    with open('models/best_model.pkl', 'rb') as f:
        model = pickle.load(f)
    with open('models/scaler.pkl', 'rb') as f:
        scaler = pickle.load(f)
    with open('models/label_encoder.pkl', 'rb') as f:
        le = pickle.load(f)
    return model, scaler, le

# Database models
class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    employee_id = db.Column(db.String(20), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    is_admin = db.Column(db.Boolean, default=False)
    predictions = db.relationship('Prediction', backref='user', lazy=True)

class Prediction(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    input_type = db.Column(db.String(20), nullable=False)  # 'single' or 'csv'
    flow_id = db.Column(db.String(50), nullable=True)  # For CSV predictions
    predicted_class = db.Column(db.String(50), nullable=False)
    confidence = db.Column(db.Float, nullable=False)
    top_classes = db.Column(db.Text, nullable=False)  # JSON string of top classes
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

# Routes
@app.route('/')
def index():
    if current_user.is_authenticated:
        if current_user.is_admin:
            return redirect(url_for('admin_dashboard'))
        return redirect(url_for('dashboard'))
    return render_template('index.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        name = request.form.get('name')
        employee_id = request.form.get('employee_id')
        password = request.form.get('password')
        
        # Check if employee ID already exists
        user = User.query.filter_by(employee_id=employee_id).first()
        if user:
            flash('Employee ID already exists!', 'danger')
            return redirect(url_for('register'))
        
        # Create new user
        new_user = User(
            name=name,
            employee_id=employee_id,
            password=generate_password_hash(password, method='pbkdf2:sha256')
        )
        
        db.session.add(new_user)
        db.session.commit()
        
        flash('Registration successful! Please login.', 'success')
        return redirect(url_for('index'))
    
    return render_template('register.html')

@app.route('/login', methods=['POST'])
def login():
    employee_id = request.form.get('employee_id')
    password = request.form.get('password')
    
    # Check for admin login (hardcoded credentials)
    if employee_id == 'admin' and password == 'admin123':
        admin = User.query.filter_by(employee_id='admin').first()
        if not admin:
            admin = User(
                name='Network Administrator',
                employee_id='admin',
                password=generate_password_hash('admin123', method='pbkdf2:sha256'),
                is_admin=True
            )
            db.session.add(admin)
            db.session.commit()
        else:
            admin.is_admin = True
            db.session.commit()
        
        login_user(admin)
        return redirect(url_for('admin_dashboard'))
    
    # Check for regular user login
    user = User.query.filter_by(employee_id=employee_id).first()
    if not user or not check_password_hash(user.password, password):
        flash('Invalid employee ID or password!', 'danger')
        return redirect(url_for('index'))
    
    login_user(user)
    return redirect(url_for('dashboard'))

@app.route('/logout')
@login_required
def logout():
    logout_user()
    return redirect(url_for('index'))

@app.route('/dashboard')
@login_required
def dashboard():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    return render_template('dashboard.html', name=current_user.name)

@app.route('/predict_single', methods=['POST'])
@login_required
def predict_single():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Get form data
    flow_duration = float(request.form.get('flow_duration'))
    tot_fwd_pkts = int(request.form.get('tot_fwd_pkts'))
    tot_bwd_pkts = int(request.form.get('tot_bwd_pkts'))
    fwd_pkt_len_mean = float(request.form.get('fwd_pkt_len_mean'))
    bwd_pkt_len_mean = float(request.form.get('bwd_pkt_len_mean'))
    flow_byts_s = float(request.form.get('flow_byts_s'))
    flow_pkts_s = float(request.form.get('flow_pkts_s'))
    flow_iat_mean = float(request.form.get('flow_iat_mean'))
    fwd_header_len = int(request.form.get('fwd_header_len'))
    bwd_header_len = int(request.form.get('bwd_header_len'))
    flow_flags = int(request.form.get('flow_flags'))
    protocol = int(request.form.get('protocol'))
    
    # Create input array
    user_input = np.array([[
        flow_duration, tot_fwd_pkts, tot_bwd_pkts, fwd_pkt_len_mean, 
        bwd_pkt_len_mean, flow_byts_s, flow_pkts_s, flow_iat_mean, 
        fwd_header_len, bwd_header_len, flow_flags, protocol
    ]])
    
    # Load models
    model, scaler, le = load_models()
    
    # Scale the input
    user_input_scaled = scaler.transform(user_input)
    
    # Make prediction
    prediction = model.predict(user_input_scaled)
    prediction_proba = model.predict_proba(user_input_scaled)
    
    # Get the predicted class name
    predicted_class = le.inverse_transform(prediction)[0]
    
    # Get the confidence
    confidence = prediction_proba[0][prediction[0]] * 100
    
    # Get top 3 probable classes
    top_3_indices = np.argsort(prediction_proba[0])[-3:][::-1]
    top_3_classes = le.inverse_transform(top_3_indices)
    top_3_probabilities = [prediction_proba[0][i] * 100 for i in top_3_indices]
    
    # Create a dictionary for top classes
    top_classes_dict = {top_3_classes[i]: top_3_probabilities[i] for i in range(3)}
    
    # Save prediction to database
    new_prediction = Prediction(
        input_type='single',
        predicted_class=predicted_class,
        confidence=confidence,
        top_classes=json.dumps(top_classes_dict),
        user_id=current_user.id
    )
    db.session.add(new_prediction)
    db.session.commit()
    
    # Redirect to prediction details page
    return redirect(url_for('prediction_details', prediction_id=new_prediction.id))

@app.route('/predict_csv', methods=['POST'])
@login_required
def predict_csv():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Check if file was uploaded
    if 'file' not in request.files:
        flash('No file uploaded!', 'danger')
        return redirect(url_for('dashboard'))
    
    file = request.files['file']
    
    if file.filename == '':
        flash('No file selected!', 'danger')
        return redirect(url_for('dashboard'))
    
    if file:
        # Save the file
        filename = str(uuid.uuid4()) + '_' + file.filename
        file_path = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        file.save(file_path)
        
        # Load the CSV data
        try:
            csv_data = pd.read_csv(file_path)
        except Exception as e:
            flash(f'Error reading CSV file: {str(e)}', 'danger')
            return redirect(url_for('dashboard'))
        
        # Check if 'Flow_ID' column exists
        if 'Flow_ID' in csv_data.columns:
            flow_ids = csv_data['Flow_ID']
            # Drop the Flow_ID column for prediction
            csv_data_features = csv_data.drop(columns=['Flow_ID'])
        else:
            flow_ids = range(1, len(csv_data) + 1)
            csv_data_features = csv_data.copy()
        
        # Load models
        model, scaler, le = load_models()
        
        # Scale the data
        try:
            csv_data_scaled = scaler.transform(csv_data_features)
        except Exception as e:
            flash(f'Error scaling data: {str(e)}', 'danger')
            return redirect(url_for('dashboard'))
        
        # Make predictions
        predictions = model.predict(csv_data_scaled)
        predictions_proba = model.predict_proba(csv_data_scaled)
        
        # Convert predictions to original labels
        predicted_classes = le.inverse_transform(predictions)
        
        # Prepare results
        results = []
        for i, flow_id in enumerate(flow_ids):
            predicted_class = predicted_classes[i]
            confidence = predictions_proba[i][predictions[i]] * 100
            
            # Get top 3 probable classes
            top_3_indices = np.argsort(predictions_proba[i])[-3:][::-1]
            top_3_classes = le.inverse_transform(top_3_indices)
            top_3_probabilities = [predictions_proba[i][j] * 100 for j in top_3_indices]
            
            # Create a dictionary for top classes
            top_classes_dict = {top_3_classes[j]: top_3_probabilities[j] for j in range(3)}
            
            # Save prediction to database
            new_prediction = Prediction(
                input_type='csv',
                flow_id=str(flow_id),
                predicted_class=predicted_class,
                confidence=confidence,
                top_classes=json.dumps(top_classes_dict),
                user_id=current_user.id
            )
            db.session.add(new_prediction)
            db.session.flush()  # Get the ID before committing
            
            # Add to results
            results.append({
                'id': new_prediction.id,
                'flow_id': str(flow_id),
                'predicted_class': predicted_class,
                'confidence': confidence,
                'top_classes': top_classes_dict
            })
        
        db.session.commit()
        
        return render_template('csv_prediction_result.html', results=results)

@app.route('/prediction_history')
@login_required
def prediction_history():
    if current_user.is_admin:
        return redirect(url_for('admin_dashboard'))
    
    # Get all predictions for the current user
    user_predictions = Prediction.query.filter_by(user_id=current_user.id).order_by(Prediction.timestamp.desc()).all()
    
    return render_template('prediction_history.html', predictions=user_predictions)

@app.route('/prediction_details/<int:prediction_id>')
@login_required
def prediction_details(prediction_id):
    prediction = Prediction.query.get_or_404(prediction_id)
    
    # Check if the current user is the owner of the prediction or an admin
    if prediction.user_id != current_user.id and not current_user.is_admin:
        flash('You are not authorized to view this prediction.', 'danger')
        return redirect(url_for('dashboard'))
    
    # Parse the top_classes string to a dictionary
    try:
        top_classes = json.loads(prediction.top_classes)
    except:
        # If JSON parsing fails, try to evaluate as a dictionary string
        try:
            top_classes = eval(prediction.top_classes)
        except:
            top_classes = {}
    
    return render_template('prediction_details.html', prediction=prediction, top_classes=top_classes)

@app.route('/admin_dashboard')
@login_required
def admin_dashboard():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    # Get all predictions
    all_predictions = Prediction.query.all()
    
    # Prepare data for visualizations
    total_traffic = len(all_predictions)
    attack_count = sum(1 for p in all_predictions if p.predicted_class != 'BENIGN')
    benign_count = total_traffic - attack_count
    
    # Attack type distribution
    attack_types = {}
    for p in all_predictions:
        if p.predicted_class != 'BENIGN':
            attack_types[p.predicted_class] = attack_types.get(p.predicted_class, 0) + 1
    
    # Recent predictions for alerts (limit to 20)
    recent_predictions = Prediction.query.order_by(Prediction.timestamp.desc()).limit(20).all()
    
    # Create visualizations
    # 1. Total Traffic vs Attack Ratio (Bar chart)
    plt.figure(figsize=(10, 6))
    plt.bar(['Benign Traffic', 'Attack Traffic'], [benign_count, attack_count], color=['green', 'red'])
    plt.title('Total Traffic vs Attack Ratio')
    plt.ylabel('Count')
    plt.tight_layout()
    
    # Convert plot to base64 string
    img1 = io.BytesIO()
    plt.savefig(img1, format='png')
    img1.seek(0)
    plot_url1 = base64.b64encode(img1.getvalue()).decode('utf8')
    plt.close()
    
    # 2. Attack Type Distribution (Pie chart)
    if attack_types:
        plt.figure(figsize=(10, 6))
        plt.pie(attack_types.values(), labels=attack_types.keys(), autopct='%1.1f%%', startangle=90)
        plt.title('Attack Type Distribution')
        plt.axis('equal')
        plt.tight_layout()
        
        # Convert plot to base64 string
        img2 = io.BytesIO()
        plt.savefig(img2, format='png')
        img2.seek(0)
        plot_url2 = base64.b64encode(img2.getvalue()).decode('utf8')
        plt.close()
    else:
        plot_url2 = None
    
    return render_template(
        'admin_dashboard.html',
        total_traffic=total_traffic,
        attack_count=attack_count,
        benign_count=benign_count,
        attack_types=attack_types,
        recent_predictions=recent_predictions,
        plot_url1=plot_url1,
        plot_url2=plot_url2
    )

@app.route('/all_predictions')
@login_required
def all_predictions():
    if not current_user.is_admin:
        return redirect(url_for('dashboard'))
    
    # Get all predictions
    all_predictions = Prediction.query.order_by(Prediction.timestamp.desc()).all()
    
    return render_template('all_predictions.html', predictions=all_predictions)

# Create database and upload folder
if not os.path.exists('database.db'):
    with app.app_context():
        db.create_all()

if not os.path.exists('uploads'):
    os.makedirs('uploads')

if __name__ == '__main__':
    app.run(debug=True)