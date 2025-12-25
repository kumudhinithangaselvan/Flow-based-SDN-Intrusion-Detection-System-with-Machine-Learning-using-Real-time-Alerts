# Flow-Based SDN Intrusion Detection System using Machine Learning with Real Time Alerts
## 📌Overview:
The Intelligent SDN Intrusion Detection System (IDS) is a flow-based traffic classification system designed to enhance the security of Software-Defined Networking (SDN) environments. The system uses Machine Learning models built with Scikit-learn and deployed through a Flask-based web application to classify network traffic as Benign or Malicious.

In addition to intrusion detection, the system provides real-time email alerts to notify the network administrator immediately when cyberattacks are detected.

The system supports:

1.Real-time single flow prediction


2.CSV-based bulk log prediction


3.User authentication (Login & Registration)


4.Admin analytics dashboard with attack distribution and logs


5.Automated email alerts on attack detection


The goal of this project is to provide a fast, scalable, and deployable SDN security solution using flow-based machine learning techniques.

## ❗Problem Statement:
SDN environments rely on a centralized controller, which makes them vulnerable to various cyberattacks such as DDoS, probing, spoofing, and botnet traffic. Traditional intrusion detection systems suffer from several limitations, including:

1.High false positive rates


2.Dependence on signature-based detection


3.Poor adaptability to new attack patterns


4.Manual and time-consuming log analysis


5.Limited scalability with high-volume SDN traffic


To overcome these challenges, a Machine Learning–based IDS that efficiently analyzes SDN flow data and supports real-time alerting is required.

## 🎯Objectives:
• Develop a robust machine learning model for SDN flow classification


• Enable real-time and batch intrusion detection


• Provide a user-friendly web interface


• Support admin monitoring through visual analytics


• Reduce false alarms while improving detection accuracy


• Design a scalable system suitable for modern SDN networks


## Key Features:
### User Features:

• User login and registration

• Single flow prediction

• CSV upload for bulk predictions

• View prediction history

### Admin Features:

• Admin login

• View all user predictions

• Attack distribution analytics

• Centralized Traffic monitoring dashboard

• Receive real-time alert emails


### ML Features:

• Complete preprocessing pipeline

• Trained models: Random Forest, SVM, Logistic Regression, Gradient Boosting

• Best model: Random Forest (91% accuracy)

• Model saved and deployed using pickle

## 🧩System Architecture:
<img width="1536" height="1024" alt="image" src="https://github.com/user-attachments/assets/c0dae682-713e-493a-85a9-08317da7984e" />


## 🗂Modules:
### Data Preprocessing

• Handling missing values

• Removing duplicates and outliers

• Label encoding

• Feature scaling

• Train-test splitting

### ML Model Training

 Evaluation metrics used

• Accuracy

• Precision

• Recall

• F1-score

• Confusion Matrix

The Random Forest classifier achieved the highest performance with 91% accuracy and was selected for deployment.

### Web Application

• User Interface includes:

• Login/Register

• Single flow prediction

•  Bulk CSV Prediction

• Prediction history

Admin Interface includes:

• Complete prediction logs

• Graphical attack analytics

• Real-time email alerts


## 🛠Tech Stack

Frontend: HTML, CSS, Bootstrap

Backend: Flask (Python)

Machine Learning: Python, Scikit-learn, Pandas, NumPy

Database: SQLite

Visualization: Matplotlib

Alerts: SMTP (Email Service)

## Output:
### Registration Page:
<img width="1600" height="801" alt="image" src="https://github.com/user-attachments/assets/34eb6745-83a6-4847-8e27-8c6b6a50a1c0" />

### Login Page:
<img width="1600" height="800" alt="image" src="https://github.com/user-attachments/assets/f234d136-8505-4bae-9f59-2f315f15bf57" />

### Employee (User) Dashboard:
<img width="1600" height="813" alt="image" src="https://github.com/user-attachments/assets/aac8e8eb-38de-402b-bb5b-0c8e54c8e789" />

### Single Flow Prediction Page:
<img width="1600" height="814" alt="image" src="https://github.com/user-attachments/assets/8d17586f-be9e-4575-a358-ee0f1c22467d" />

### CSV Upload & Bulk Prediction Result:
<img width="1600" height="818" alt="image" src="https://github.com/user-attachments/assets/7393afc2-a8fc-4f7e-b533-00072aac9c67" />

### Admin Dashboard:
<img width="1600" height="808" alt="image" src="https://github.com/user-attachments/assets/e23a617b-44b8-4c35-a04d-f8b4af0260f6" />

### Prediction History and Log Records:
<img width="1600" height="625" alt="image" src="https://github.com/user-attachments/assets/19c87b6f-c5a9-4452-9bba-1b00840d3ab1" />

### Real-Time Email Alert for Detected Attack:
<img width="1600" height="810" alt="image" src="https://github.com/user-attachments/assets/abb8512a-ffa9-4fef-b3a5-00a07b25b2af" />

## 📊Results:
• Achieved 91% accuracy using Random Forest

• Accurate detection of multiple attack types

• User- and admin-friendly web interface

• Real-time alert notification on attack detection

• Analytical dashboard for effective monitoring

## 🔮Future Enhancements:

• Online and adaptive learning

• Multi-controller SDN support

• Automated attack mitigation via SDN controller rules

• Deployment on real SDN testbeds

• Cloud deployment (AWS / Azure)

• Enhanced role-based authentication and UI

## Author

KUMUDHINI T

B.E - Computer Science And Engineering
