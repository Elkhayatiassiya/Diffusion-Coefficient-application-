from flask import Flask, render_template, redirect, url_for, request, flash, session, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_mail import Mail, Message
from werkzeug.security import generate_password_hash, check_password_hash
from itsdangerous import URLSafeTimedSerializer, SignatureExpired
import numpy as np
import os
import time
from config import Config
from flask_migrate import Migrate

# -------------------- CONFIGURATION -------------------- #
app = Flask(__name__, template_folder="templates")
app.config.from_object(Config)
app.secret_key = app.config['SECRET_KEY']

# Debug complet de la configuration email
print("\n=== CONFIGURATION EMAIL ===")
print(f"Serveur SMTP : {app.config['MAIL_SERVER']}")
print(f"Port : {app.config['MAIL_PORT']}")
print(f"TLS : {app.config['MAIL_USE_TLS']} | SSL : {app.config['MAIL_USE_SSL']}")
print(f"Expéditeur : {app.config['MAIL_DEFAULT_SENDER']}")
print(f"Username : {app.config['MAIL_USERNAME']}")
print(f"Password configurée : {'*'*len(app.config['MAIL_PASSWORD']) if app.config['MAIL_PASSWORD'] else 'AUCUN MOT DE PASSE TROUVÉ'}")
print(f"Sender : {app.config['MAIL_DEFAULT_SENDER']}\n")

# Initialisation des extensions
db = SQLAlchemy(app)
migrate = Migrate(app, db)
mail = Mail(app)
s = URLSafeTimedSerializer(app.config['SECRET_KEY'])

# -------------------- MODELE UTILISATEUR -------------------- #
class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(100), unique=True, nullable=False)
    firstname = db.Column(db.String(100), nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    failed_login_attempts = db.Column(db.Integer, default=0)
    last_failed_login = db.Column(db.Integer, default=0)
# -------------------- CALCUL COEFF DE DIFFUSION -------------------- #
def calcul_diffusion(x_A, D_AB0, D_BA0, phi_A, phi_B, lambda_A, lambda_B,
                     theta_BA, theta_AB, theta_AA, theta_BB, tau_AB, tau_BA, q_A, q_B):
    x_B = 1 - x_A
    ln_D_AB0 = np.log(D_AB0)
    ln_D_BA0 = np.log(D_BA0)

    first_term = x_B * ln_D_AB0 + x_A * ln_D_BA0
    second_term = 2 * (x_A * np.log(x_A / phi_A) + x_B * np.log(x_B / phi_B))
    third_term = 2 * x_A * x_B * (
        (phi_A / x_A) * (1 - lambda_A / lambda_B) +
        (phi_B / x_B) * (1 - lambda_B / lambda_A)
    )
    fourth_term = x_B * q_A * (
        (1 - theta_BA**2) * np.log(tau_BA) +
        (1 - theta_BB**2) * np.log(tau_AB) * tau_AB
    )
    fifth_term = x_A * q_B * (
        (1 - theta_AB**2) * np.log(tau_AB) +
        (1 - theta_AA**2) * np.log(tau_BA) * tau_BA
    )
    ln_D_AB = first_term + second_term + third_term + fourth_term + fifth_term
    D_AB = np.exp(ln_D_AB)

    D_exp = 1.33e-5
    error = abs(D_AB - D_exp) / D_exp * 100
    return D_AB, error

# -------------------- ROUTES -------------------- #
@app.route('/')
def home():
    return render_template('home.html')

@app.route('/signup', methods=['GET', 'POST'])
def signup():
    if request.method == 'POST':
        username = request.form.get('username')
        firstname = request.form.get('firstname')
        email = request.form.get('email')
        password = request.form.get('password')

        if len(password) < 8 or not any(c.isupper() for c in password) or not any(c.isdigit() for c in password):
            flash("Le mot de passe doit contenir au moins 8 caractères, une majuscule et un chiffre.")
            return redirect(url_for('signup'))

        if not all([username, firstname, email, password]):
            flash("Tous les champs sont obligatoires.")
            return redirect(url_for('signup'))

        if User.query.filter_by(email=email).first():
            flash("Email déjà utilisé.")
            return redirect(url_for('signup'))

        hashed_pw = generate_password_hash(password, method='pbkdf2:sha256')
        new_user = User(username=username, firstname=firstname, email=email, password=hashed_pw)
        db.session.add(new_user)
        db.session.commit()
        flash("Compte créé ! Connectez-vous.")
        return redirect(url_for('login'))
    return render_template('signup.html')

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        email = request.form.get('email')
        password = request.form.get('password')
        user = User.query.filter_by(email=email).first()

        if not email or not password:
            flash("Please fill in all fields.")
            return redirect(url_for('login'))

        if user:
            current_time = time.time()
            if user.failed_login_attempts >= 3:
                time_since_last_attempt = current_time - user.last_failed_login
                if time_since_last_attempt < 60:
                    flash("Too many attempts. Please wait 1 minute before trying again.")
                    return redirect(url_for('login'))
                else:
                    user.failed_login_attempts = 0
                    db.session.commit()

            if check_password_hash(user.password, password):
                session['user_id'] = user.id
                user.failed_login_attempts = 0
                db.session.commit()
                return redirect(url_for('formulaire'))
            else:
                user.failed_login_attempts += 1
                user.last_failed_login = current_time
                db.session.commit()
                remaining_attempts = 3 - user.failed_login_attempts
                if remaining_attempts > 0:
                    flash(f"Incorrect password. You have {remaining_attempts} attempts left.")
                else:
                    flash("Too many incorrect attempts. Please wait 1 minute before retrying.")
                return redirect(url_for('login'))
        else:
            flash("Incorrect email or password.")
            return redirect(url_for('login'))
    return render_template('login.html')

@app.route('/forgot-password', methods=['GET', 'POST'])
def forgot_password():
    if request.method == 'POST':
        email = request.form.get('email')
        user = User.query.filter_by(email=email).first()
        if user:
            try:
                token = s.dumps(email, salt='email-reset')
                reset_url = url_for('reset_password', token=token, _external=True)
                
                msg = Message('Réinitialisation du mot de passe',
                            sender=app.config['MAIL_DEFAULT_SENDER'],
                            recipients=[email])
                msg.body = f'''Pour réinitialiser votre mot de passe, visitez le lien suivant:
{reset_url}

Si vous n'avez pas demandé de réinitialisation, ignorez simplement cet email.
'''
                mail.send(msg)
                flash('Un email avec les instructions de réinitialisation a été envoyé.', 'success')
            except Exception as e:
                app.logger.error(f"Erreur d'envoi d'email: {str(e)}")
                flash(f"Erreur lors de l'envoi: {str(e)}", 'error')
        else:
            flash("Cet email n'est associé à aucun compte.", 'error')
        return redirect(url_for('forgot_password'))
    return render_template('forgot_password.html')

@app.route('/reset/<token>', methods=['GET', 'POST'])
def reset_password(token):
    try:
        email = s.loads(token, salt='email-reset', max_age=600)
    except SignatureExpired:
        flash("Le lien de réinitialisation a expiré.", 'error')
        return redirect(url_for('forgot_password'))
    except:
        flash("Lien invalide.", 'error')
        return redirect(url_for('forgot_password'))

    if request.method == 'POST':
        new_password = request.form.get('password')
        confirm = request.form.get('confirm')

        if not new_password or not confirm:
            flash("Tous les champs sont requis.", 'error')
        elif new_password != confirm:
            flash("Les mots de passe ne correspondent pas.", 'error')
        elif len(new_password) < 8 or not any(c.isupper() for c in new_password) or not any(c.isdigit() for c in new_password):
            flash("Le mot de passe doit contenir au moins 8 caractères, une majuscule et un chiffre.", 'error')
        else:
            user = User.query.filter_by(email=email).first()
            if user:
                user.password = generate_password_hash(new_password, method='pbkdf2:sha256')
                db.session.commit()
                flash("Mot de passe mis à jour avec succès! Veuillez vous connecter avec votre nouveau mot de passe.", 'success')
                return redirect(url_for('login'))
            else:
                flash("Utilisateur non trouvé.", 'error')
    
    return render_template('reset.html')

@app.route('/logout')
def logout():
    session.pop('user_id', None)
    flash("Vous avez été déconnecté.", 'success')
    return redirect(url_for('login'))

@app.route('/formulaire', methods=['GET'])
def formulaire():
    if 'user_id' not in session:
        flash("Veuillez vous connecter pour accéder à cette page.", 'error')
        return redirect(url_for('login'))
    return render_template('formulaire.html')

@app.route('/resultat', methods=['POST'])
def resultat():
    try:
        x_A = float(request.form['x_A'])
        D_AB0 = float(request.form['D_AB0'])
        D_BA0 = float(request.form['D_BA0'])
        phi_A = float(request.form['phi_A'])
        phi_B = float(request.form['phi_B'])
        lambda_A = float(request.form['lambda_A'])
        lambda_B = float(request.form['lambda_B'])
        theta_BA = float(request.form['theta_BA'])
        theta_AB = float(request.form['theta_AB'])
        theta_AA = float(request.form['theta_AA'])
        theta_BB = float(request.form['theta_BB'])
        tau_AB = float(request.form['tau_AB'])
        tau_BA = float(request.form['tau_BA'])
        q_A = float(request.form['q_A'])
        q_B = float(request.form['q_B'])

        D_AB, error = calcul_diffusion(x_A, D_AB0, D_BA0, phi_A, phi_B, lambda_A, lambda_B, # type: ignore
                                       theta_BA, theta_AB, theta_AA, theta_BB, tau_AB, tau_BA, q_A, q_B)

        flash(f"Résultat du calcul : D_AB = {D_AB}, erreur = {error}%")
        return redirect(url_for('formulaire'))

    except Exception as e:
        flash(f"Erreur lors du traitement : {e}")
        return redirect(url_for('formulaire'))
# ... (toutes vos routes existantes comme /login, /forgot-password, etc.)



if __name__ == '__main__':
    # Test SMTP au démarrage
    try:
        with app.app_context():
            test_msg = Message(
                subject="Test SMTP - Configuration réussie",
                sender=app.config['MAIL_DEFAULT_SENDER'],
                recipients=[app.config['MAIL_USERNAME']],  # Envoi à vous-même
                body="Votre configuration SMTP fonctionne correctement!"
            )
            mail.send(test_msg)
            print("\n=== TEST SMTP RÉUSSI ===")
            print("Un email de test a été envoyé avec succès!")
    except Exception as e:
        print("\n=== ERREUR SMTP ===")
        print(f"Erreur lors du test SMTP: {str(e)}")
        print("Vérifiez votre configuration dans .env")
    
    app.run(debug=True)