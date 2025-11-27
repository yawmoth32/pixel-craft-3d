# app.py - VERSION FINAL SEGURA Y FUNCIONAL
import os
from datetime import datetime
import secrets
from flask import Flask, render_template, request, redirect, url_for, flash, send_from_directory, session
from flask_sqlalchemy import SQLAlchemy
from flask_login import LoginManager, UserMixin, login_user, login_required, logout_user, current_user
from flask_talisman import Talisman
from flask_wtf.csrf import CSRFProtect
from flask_limiter import Limiter
from flask_limiter.util import get_remote_address
from werkzeug.security import generate_password_hash, check_password_hash
from werkzeug.utils import secure_filename
import smtplib
import re
from email.mime.text import MIMEText
from email.mime.multipart import MIMEMultipart
from sqlalchemy import func

# Cargar variables de entorno
try:
    from dotenv import load_dotenv
    load_dotenv()
except ImportError:
    pass

app = Flask(__name__)
app.config['SECRET_KEY'] = os.environ.get('SECRET_KEY') or secrets.token_hex(32)
app.config['SQLALCHEMY_DATABASE_URI'] = os.environ.get('DATABASE_URL') or 'sqlite:///database.db'
app.config['UPLOAD_FOLDER'] = os.path.join('static', 'uploads')
app.config['MAX_CONTENT_LENGTH'] = 16 * 1024 * 1024  # 16MB max
app.config['MAIL_SERVER'] = 'smtp.gmail.com'
app.config['MAIL_PORT'] = 587
app.config['MAIL_USE_TLS'] = True
app.config['MAIL_USERNAME'] = 'theroce86@gmail.com'
app.config['MAIL_PASSWORD'] = os.environ.get('MAIL_PASSWORD')

# ✅ SEGURIDAD: Talisman (HTTPS y headers)
csp = {
    'default-src': ["'self'"],
    'script-src': ["'self'", "'unsafe-inline'"],
    'style-src': ["'self'", "'unsafe-inline'"],
    'img-src': ["'self'", "data:", "https://*"],
    'font-src': ["'self'"],
    'connect-src': ["'self'"],
}
Talisman(app, 
         force_https_permanent=True,
         strict_transport_security=True,
         strict_transport_security_max_age=31536000,
         content_security_policy=csp,
         referrer_policy='strict-origin-when-cross-origin')

# ✅ SEGURIDAD: CSRF Protection
csrf = CSRFProtect(app)

# ✅ SEGURIDAD: Rate Limiting
limiter = Limiter(
    key_func=get_remote_address,
    app=app,
    default_limits=["200 per day", "50 per hour"]
)

os.makedirs(app.config['UPLOAD_FOLDER'], exist_ok=True)

db = SQLAlchemy(app)
login_manager = LoginManager()
login_manager.init_app(app)
login_manager.login_view = 'login'
login_manager.login_message = "Por favor inicia sesión para acceder."
login_manager.login_message_category = "info"

FORBIDDEN_WORDS = [
    'yawmoth', 'admin', 'dueño', 'pendejo', 'imbécil', 'idiota', 'estafa', 
    'fraude', 'mentiroso', 'ladrón', 'roba', 'mata', 'muere', 'odio', 
    'odio a', 'no recomiendo', 'no compren', 'eviten', 'abusivo', 'abusiva'
]

class User(UserMixin, db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(80), unique=True, nullable=False)
    email = db.Column(db.String(120), unique=True, nullable=False)
    password_hash = db.Column(db.String(128))
    role = db.Column(db.String(20), default='user')
    nombre = db.Column(db.String(80))
    apellido = db.Column(db.String(80))
    telefono = db.Column(db.String(20))
    direccion = db.Column(db.String(200))
    def set_password(self, password):
        self.password_hash = generate_password_hash(password)
    def check_password(self, password):
        return check_password_hash(self.password_hash, password)

class Product(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    description = db.Column(db.Text)
    price = db.Column(db.Float, nullable=False)
    category = db.Column(db.String(50))
    image_filename = db.Column(db.String(100))
    stock = db.Column(db.Integer, default=0)
    views = db.Column(db.Integer, default=0)
    total_sold = db.Column(db.Integer, default=0)

class CartItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer, default=1)
    user = db.relationship('User', backref='cart_items')
    product = db.relationship('Product')

class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'))
    date = db.Column(db.DateTime, default=datetime.utcnow)
    status = db.Column(db.String(20), default='pendiente')
    user = db.relationship('User', backref='orders')

class OrderItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    order_id = db.Column(db.Integer, db.ForeignKey('order.id'))
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'))
    quantity = db.Column(db.Integer)
    price_at_time = db.Column(db.Float)
    order = db.relationship('Order', backref='items')
    product = db.relationship('Product')

class Review(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    product_id = db.Column(db.Integer, db.ForeignKey('product.id'), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey('user.id'), nullable=False)
    rating = db.Column(db.Integer, nullable=False)
    comment = db.Column(db.Text, nullable=False)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    approved = db.Column(db.Boolean, default=False)
    product = db.relationship('Product', backref='reviews')
    user = db.relationship('User', backref='reviews')

class SiteSettings(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    location = db.Column(db.String(100), default="Tucumán, Argentina")
    whatsapp = db.Column(db.String(20), default="+5493814499884")
    instagram = db.Column(db.String(50))
    facebook = db.Column(db.String(50))
    youtube = db.Column(db.String(50))
    tiktok = db.Column(db.String(50))
    updated_at = db.Column(db.DateTime, default=datetime.utcnow)

@login_manager.user_loader
def load_user(user_id):
    return User.query.get(int(user_id))

with app.app_context():
    db.create_all()
    if not User.query.filter_by(username='Yawmoth32').first():
        admin = User(
            username='Yawmoth32',
            email='theroce86@gmail.com',
            role='admin'
        )
        admin.set_password('C@ne2488')
        db.session.add(admin)
        db.session.commit()
        print("✅ Cuenta admin creada: Yawmoth32 / C@ne2488")

@app.context_processor
def inject_settings():
    settings = SiteSettings.query.first()
    if not settings:
        settings = SiteSettings()
        db.session.add(settings)
        db.session.commit()
    return dict(settings=settings)

# ✅ VALIDAR EXTENSIONES PERMITIDAS
def allowed_file(filename):
    ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif', 'svg'}
    return '.' in filename and \
           filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS

# ✅ SANITIZAR ENTRADAS
def sanitize_input(text):
    import html
    if isinstance(text, str):
        return html.escape(text)
    return text

def send_order_email(order):
    user = order.user
    msg = MIMEMultipart('alternative')
    msg['From'] = app.config['MAIL_USERNAME']
    msg['To'] = 'theroce86@gmail.com'
    msg['Subject'] = f'🛒 Nuevo pedido #{order.id} - Pixel Craft 3D'

    # Sanitizar datos
    name = sanitize_input(f"{user.nombre} {user.apellido}")
    username = sanitize_input(user.username)
    phone = sanitize_input(user.telefono or 'No especificado')
    address = sanitize_input(user.direccion or 'No especificada')

    html_body = f"""
    <html>
    <head>
        <style>
            body {{
                font-family: 'Segoe UI', sans-serif;
                background: url('https://i.imgur.com/6J8QK9Z.png') no-repeat center center fixed;
                background-size: cover;
                margin: 0;
                padding: 20px;
                color: white;
                line-height: 1.6;
                background-color: rgba(0, 0, 0, 0.8);
            }}
            .container {{
                max-width: 600px;
                margin: 0 auto;
                background: rgba(20, 20, 30, 0.9);
                border-radius: 12px;
                box-shadow: 0 0 20px rgba(0, 255, 255, 0.3);
                padding: 2rem;
                border: 2px solid rgba(0, 255, 255, 0.5);
                backdrop-filter: blur(10px);
            }}
            h1 {{
                color: #0ff;
                text-shadow: 0 0 5px #0ff;
                font-size: 1.8rem;
                margin-bottom: 0.5rem;
            }}
            h2 {{
                color: #0ff;
                text-shadow: 0 0 5px #0ff;
                font-size: 1.4rem;
                margin-top: 1.5rem;
                border-bottom: 2px solid #0ff;
                padding-bottom: 0.5rem;
            }}
            p {{
                margin: 0.5rem 0;
                color: #ddd;
            }}
            .highlight {{
                color: #0ff;
                font-weight: bold;
            }}
            .product-list {{
                margin: 1rem 0;
                padding: 1rem;
                background: rgba(40, 40, 50, 0.7);
                border-radius: 8px;
            }}
            .total {{
                font-size: 1.2rem;
                font-weight: bold;
                color: #0ff;
                margin-top: 1rem;
                text-align: right;
            }}
            .footer {{
                margin-top: 2rem;
                text-align: center;
                font-size: 0.9rem;
                color: #aaa;
                border-top: 1px dashed #0ff;
                padding-top: 1rem;
            }}
            .logo {{
                width: 100px;
                height: 100px;
                display: block;
                margin: 0 auto 1rem;
                border-radius: 50%;
                box-shadow: 0 0 15px rgba(0, 255, 255, 0.5);
                border: 2px solid rgba(0, 255, 255, 0.3);
            }}
        </style>
    </head>
    <body>
        <div class="container">
            <img src="https://i.imgur.com/6J8QK9Z.png" alt="Pixel Craft 3D" class="logo">
            <h1>🛒 Nuevo pedido #{order.id}</h1>
            <p><strong>📅 Fecha:</strong> {order.date.strftime('%d/%m/%Y %H:%M')}</p>

            <h2>👤 Datos del cliente</h2>
            <p><strong>Nombre:</strong> <span class="highlight">{name}</span></p>
            <p><strong>Usuario:</strong> <span class="highlight">@{username}</span></p>
            <p><strong>Teléfono:</strong> {phone}</p>
            <p><strong>Dirección:</strong> {address}</p>

            <h2>📦 Productos</h2>
            <div class="product-list">
    """

    total = 0
    for item in order.items:
        product_name = sanitize_input(item.product.name)
        html_body += f"<p>- {product_name} x{item.quantity} → $ {item.price_at_time:.2f} (subtotal: $ {item.price_at_time * item.quantity:.2f})</p>\n"
        total += item.price_at_time * item.quantity

    html_body += f"""
            </div>
            <div class="total">💰 Total estimado: $ {total:.2f}</div>

            <h2>ℹ️ Nota</h2>
            <p>Estaremos comunicándonos con el cliente a la brevedad para finalizar el pedido.</p>

            <div class="footer">
                <p>&copy; {datetime.now().year} Pixel Craft 3D — Dando forma a tus ideas, tu mente es el límite.</p>
            </div>
        </div>
    </body>
    </html>
    """

    plain_body = f"""
    ¡Nuevo pedido recibido!

    📋 Número de pedido: #{order.id}
    📅 Fecha: {order.date.strftime('%d/%m/%Y %H:%M')}

    👤 Datos del cliente:
    Nombre: {name}
    Usuario: @{username}
    Teléfono: {phone}
    Dirección: {address}

    📦 Productos:
    """
    for item in order.items:
        product_name = sanitize_input(item.product.name)
        plain_body += f"- {product_name} x{item.quantity} → $ {item.price_at_time:.2f} (subtotal: $ {item.price_at_time * item.quantity:.2f})\n"
    plain_body += f"\n💰 Total estimado: $ {total:.2f}\n\n"
    plain_body += "ℹ️ Nota: Estaremos contactándote pronto."

    msg.attach(MIMEText(plain_body, 'plain', 'utf-8'))
    msg.attach(MIMEText(html_body, 'html', 'utf-8'))

    try:
        server = smtplib.SMTP(app.config['MAIL_SERVER'], app.config['MAIL_PORT'])
        server.starttls()
        server.login(app.config['MAIL_USERNAME'], app.config['MAIL_PASSWORD'])
        server.sendmail(msg['From'], msg['To'], msg.as_string())
        server.quit()
        print(f"✅ Correo enviado para pedido #{order.id}")
    except Exception as e:
        print(f"❌ Error al enviar correo: {e}")
        flash("⚠️ Error al notificar al administrador. Por favor, contacte directamente.")

# ✅ RUTAS
@app.route('/')
def index():
    products = Product.query.all()
    categories = db.session.query(Product.category).distinct().filter(Product.category != None).all()
    top_sold = Product.query.order_by(Product.total_sold.desc()).limit(3).all()
    most_viewed = Product.query.order_by(Product.views.desc()).first()
    most_reviewed = db.session.query(
        Product,
        func.count(Review.id).label('review_count')
    ).join(Review, Review.product_id == Product.id)\
     .filter(Review.approved == True)\
     .group_by(Product.id)\
     .order_by(func.count(Review.id).desc())\
     .first()
    most_reviewed_product = most_reviewed[0] if most_reviewed else None
    settings = SiteSettings.query.first()
    return render_template('index.html', 
                         products=products, 
                         categories=categories,
                         top_sold=top_sold,
                         most_viewed=most_viewed,
                         most_reviewed=most_reviewed_product,
                         settings=settings,
                         now=datetime.now())

@app.route('/register', methods=['GET', 'POST'])
@limiter.limit("3 per hour")
def register():
    if request.method == 'POST':
        username = request.form['username'].strip()
        email = request.form['email'].strip().lower()
        password = request.form['password']
        
        if len(username) < 3 or len(username) > 20 or not username.replace('_', '').isalnum():
            flash('⚠️ Usuario inválido (3-20 caracteres, solo letras, números y _)')
            return redirect('/register')
        
        if not re.match(r"[^@]+@[^@]+\.[^@]+", email):
            flash('⚠️ Email inválido')
            return redirect('/register')
        
        if User.query.filter_by(username=username).first():
            flash('⚠️ Usuario ya existe.')
            return redirect('/register')
        if User.query.filter_by(email=email).first():
            flash('⚠️ Email ya registrado.')
            return redirect('/register')
        
        if len(password) < 8:
            flash('🔒 Mínimo 8 caracteres.')
            return redirect('/register')
        if not re.search(r'[A-Z]', password):
            flash('🔒 Incluye una mayúscula.')
            return redirect('/register')
        if not re.search(r'[a-z]', password):
            flash('🔒 Incluye una minúscula.')
            return redirect('/register')
        if not re.search(r'\d', password):
            flash('🔒 Incluye un número.')
            return redirect('/register')
        if not re.search(r'[^A-Za-z0-9]', password):
            flash('🔒 Incluye un símbolo (!, @, #).')
            return redirect('/register')
        
        user = User(username=username, email=email)
        user.set_password(password)
        db.session.add(user)
        db.session.commit()
        flash('✅ Registro exitoso. Completa tu perfil.')
        login_user(user)
        return redirect('/profile')
    settings = SiteSettings.query.first()
    return render_template('register.html', settings=settings, now=datetime.now())

@app.route('/login', methods=['GET', 'POST'])
@limiter.limit("5 per minute")
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        user = User.query.filter_by(username=username).first()
        if user and user.check_password(password):
            login_user(user)
            return redirect('/profile' if user.nombre else '/')
        flash('❌ Usuario o contraseña incorrectos')
    settings = SiteSettings.query.first()
    return render_template('login.html', settings=settings, now=datetime.now())

@app.route('/logout')
@login_required
def logout():
    logout_user()
    session.clear()
    return redirect('/')

@app.route('/profile', methods=['GET', 'POST'])
@login_required
def profile():
    if request.method == 'POST':
        current_user.nombre = sanitize_input(request.form['nombre'][:80])
        current_user.apellido = sanitize_input(request.form['apellido'][:80])
        current_user.telefono = sanitize_input(request.form['telefono'][:20])
        current_user.direccion = sanitize_input(request.form['direccion'][:200])
        db.session.commit()
        flash('✅ Perfil actualizado')
        return redirect('/')
    settings = SiteSettings.query.first()
    return render_template('profile.html', user=current_user, settings=settings, now=datetime.now())

@app.route('/cart')
@login_required
def cart():
    items = CartItem.query.filter_by(user_id=current_user.id).all()
    total = sum(item.product.price * item.quantity for item in items)
    settings = SiteSettings.query.first()
    return render_template('cart.html', items=items, total=total, settings=settings, now=datetime.now())

@app.route('/cart/add/<int:product_id>')
@login_required
def add_to_cart(product_id):
    product = Product.query.get_or_404(product_id)
    if product.stock <= 0:
        flash(f'❌ "{product.name}" está agotado.')
        return redirect('/')
    
    item = CartItem.query.filter_by(user_id=current_user.id, product_id=product_id).first()
    if item:
        if item.quantity >= product.stock:
            flash(f'⚠️ Solo hay {product.stock} unidad(es) disponibles de "{product.name}".')
            return redirect('/cart')
        item.quantity += 1
    else:
        item = CartItem(user_id=current_user.id, product_id=product_id, quantity=1)
        db.session.add(item)
    db.session.commit()
    flash(f'🛒 "{product.name}" agregado al carrito.')
    return redirect('/')

@app.route('/cart/remove/<int:item_id>')
@login_required
def remove_from_cart(item_id):
    item = CartItem.query.get_or_404(item_id)
    if item.user_id == current_user.id:
        db.session.delete(item)
        db.session.commit()
    return redirect('/cart')

@app.route('/checkout', methods=['POST'])
@login_required
def checkout():
    if not (current_user.nombre and current_user.apellido and current_user.direccion):
        flash('⚠️ Completa tu perfil primero.')
        return redirect('/profile')
    cart_items = CartItem.query.filter_by(user_id=current_user.id).all()
    if not cart_items:
        flash('🛒 Carrito vacío.')
        return redirect('/cart')
    order = Order(user_id=current_user.id)
    db.session.add(order)
    db.session.flush()
    for item in cart_items:
        order_item = OrderItem(
            order_id=order.id,
            product_id=item.product_id,
            quantity=item.quantity,
            price_at_time=item.product.price
        )
        db.session.add(order_item)
        db.session.delete(item)
        product = Product.query.get(item.product_id)
        product.total_sold += item.quantity
    db.session.commit()
    send_order_email(order)
    flash(f'✅ Pedido #{order.id} recibido. ¡Te contactaremos pronto!')
    return redirect('/')

@app.route('/product/<int:product_id>')
def product_detail(product_id):
    product = Product.query.get_or_404(product_id)
    product.views += 1
    db.session.commit()
    approved_reviews = Review.query.filter_by(product_id=product_id, approved=True).order_by(Review.created_at.desc()).all()
    settings = SiteSettings.query.first()
    return render_template('product_detail.html', product=product, reviews=approved_reviews, settings=settings, now=datetime.now())

@app.route('/product/<int:product_id>/review', methods=['POST'])
@login_required
def add_review(product_id):
    product = Product.query.get_or_404(product_id)
    rating = int(request.form.get('rating', 0))
    comment = request.form.get('comment', '').strip()
    if not (1 <= rating <= 5):
        flash('⚠️ Calificación: 1 a 5 estrellas.')
        return redirect(url_for('product_detail', product_id=product_id))
    if len(comment) < 10:
        flash('⚠️ Mínimo 10 caracteres.')
        return redirect(url_for('product_detail', product_id=product_id))
    comment_lower = comment.lower()
    for word in FORBIDDEN_WORDS:
        if word in comment_lower:
            flash('❌ Comentario no permitido.')
            return redirect(url_for('product_detail', product_id=product_id))
    review = Review(
        product_id=product_id,
        user_id=current_user.id,
        rating=rating,
        comment=comment,
        approved=False
    )
    db.session.add(review)
    db.session.commit()
    flash('✅ ¡Gracias! Será revisado pronto.')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/review/<int:review_id>/approve')
@login_required
def approve_review(review_id):
    if current_user.role != 'admin':
        flash('⚠️ Acceso denegado.')
        return redirect('/')
    review = Review.query.get_or_404(review_id)
    review.approved = True
    db.session.commit()
    flash('✅ Comentario publicado.')
    return redirect(url_for('product_detail', product_id=review.product_id))

@app.route('/review/<int:review_id>/delete')
@login_required
def delete_review(review_id):
    if current_user.role != 'admin':
        flash('⚠️ Acceso denegado.')
        return redirect('/')
    review = Review.query.get_or_404(review_id)
    product_id = review.product_id
    db.session.delete(review)
    db.session.commit()
    flash('🗑️ Comentario eliminado.')
    return redirect(url_for('product_detail', product_id=product_id))

@app.route('/admin', methods=['GET', 'POST'])
@login_required
def admin():
    if current_user.role != 'admin':
        return redirect('/')
    if request.method == 'POST':
        product_id = request.form.get('product_id')
        if product_id:
            product = Product.query.get_or_404(product_id)
        else:
            product = Product()
        
        product.name = sanitize_input(request.form['name'][:100])
        product.description = sanitize_input(request.form['description'][:1000])
        try:
            product.price = float(request.form['price'])
            product.stock = int(request.form.get('stock', 0))
        except (ValueError, TypeError):
            flash('⚠️ Precio o stock inválido.')
            return redirect('/admin')
        
        category = sanitize_input(request.form['category'][:50])
        if not category:
            category = sanitize_input(request.form.get('category_custom', '').strip()[:50])
            if not category:
                flash('⚠️ Debes ingresar una categoría.')
                return redirect('/admin')
        product.category = category

        image = request.files['image']
        if image and image.filename:
            if not allowed_file(image.filename):
                flash('⚠️ Tipo de archivo no permitido. Solo PNG, JPG, JPEG, GIF.')
                return redirect('/admin')
            
            filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}")
            filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
            image.save(filepath)
            
            # ✅ Validación de imagen (con manejo de errores)
            try:
                from PIL import Image
                with Image.open(filepath) as img:
                    img.verify()
            except ImportError:
                # Pillow no instalado, omitir validación
                pass
            except Exception:
                os.remove(filepath)
                flash('⚠️ Archivo no es una imagen válida.')
                return redirect('/admin')
            
            if product.id and product.image_filename:
                old_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
                if os.path.exists(old_path):
                    os.remove(old_path)
            product.image_filename = filename

        if not product.id:
            db.session.add(product)
        db.session.commit()
        flash(f'✅ {"Producto actualizado" if product_id else "Producto agregado"}')
        return redirect('/admin')
    
    products = Product.query.all()
    categories = db.session.query(Product.category).distinct().filter(Product.category != None).all()
    settings = SiteSettings.query.first()
    return render_template('admin.html', products=products, categories=categories, settings=settings, now=datetime.now())

@app.route('/admin/edit/<int:product_id>')
@login_required
def edit_product_form(product_id):
    if current_user.role != 'admin':
        return redirect('/')
    product = Product.query.get_or_404(product_id)
    categories = db.session.query(Product.category).distinct().filter(Product.category != None).all()
    products = Product.query.all()
    settings = SiteSettings.query.first()
    return render_template('admin.html', edit_product=product, categories=categories, products=products, settings=settings, now=datetime.now())

@app.route('/admin/edit/<int:product_id>', methods=['POST'])
@login_required
def edit_product(product_id):
    if current_user.role != 'admin':
        return redirect('/')
    
    product = Product.query.get_or_404(product_id)
    
    product.name = sanitize_input(request.form['name'][:100])
    product.description = sanitize_input(request.form['description'][:1000])
    try:
        product.price = float(request.form['price'])
        product.stock = int(request.form.get('stock', 0))
    except (ValueError, TypeError):
        flash('⚠️ Precio o stock inválido.')
        return redirect(f'/admin/edit/{product_id}')
    
    category = sanitize_input(request.form['category'][:50])
    if not category:
        category = sanitize_input(request.form.get('category_custom', '').strip()[:50])
        if not category:
            flash('⚠️ Debes ingresar una categoría.')
            return redirect(f'/admin/edit/{product_id}')
    product.category = category

    image = request.files['image']
    if image and image.filename:
        if not allowed_file(image.filename):
            flash('⚠️ Tipo de archivo no permitido. Solo PNG, JPG, JPEG, GIF.')
            return redirect(f'/admin/edit/{product_id}')
        
        filename = secure_filename(f"{datetime.now().strftime('%Y%m%d%H%M%S')}_{image.filename}")
        filepath = os.path.join(app.config['UPLOAD_FOLDER'], filename)
        image.save(filepath)
        
        try:
            from PIL import Image
            with Image.open(filepath) as img:
                img.verify()
        except ImportError:
            pass
        except Exception:
            os.remove(filepath)
            flash('⚠️ Archivo no es una imagen válida.')
            return redirect(f'/admin/edit/{product_id}')
        
        if product.image_filename:
            old_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
            if os.path.exists(old_path):
                os.remove(old_path)
        product.image_filename = filename

    db.session.commit()
    flash(f'✅ Producto "{product.name}" actualizado.')
    return redirect('/admin')

@app.route('/admin/product/<int:product_id>/delete')
@login_required
def delete_product(product_id):
    if current_user.role != 'admin':
        flash('⚠️ Acceso denegado.')
        return redirect('/')
    product = Product.query.get_or_404(product_id)
    if product.image_filename:
        image_path = os.path.join(app.config['UPLOAD_FOLDER'], product.image_filename)
        if os.path.exists(image_path):
            os.remove(image_path)
    db.session.delete(product)
    db.session.commit()
    flash(f'🗑️ Producto "{product.name}" eliminado.')
    return redirect('/admin')

@app.route('/admin/settings', methods=['GET', 'POST'])
@login_required
def admin_settings():
    if current_user.role != 'admin':
        return redirect('/')
    
    settings = SiteSettings.query.first()
    if not settings:
        settings = SiteSettings()
        db.session.add(settings)
        db.session.commit()
    
    if request.method == 'POST':
        settings.location = sanitize_input(request.form['location'][:100])
        settings.whatsapp = sanitize_input(request.form['whatsapp'][:20])
        settings.instagram = sanitize_input(request.form['instagram'][:50])
        settings.facebook = sanitize_input(request.form['facebook'][:50])
        settings.youtube = sanitize_input(request.form['youtube'][:50])
        settings.tiktok = sanitize_input(request.form['tiktok'][:50])
        settings.updated_at = datetime.utcnow()
        db.session.commit()
        flash('✅ Configuración del sitio actualizada.')
        return redirect('/admin/settings')
    
    return render_template('admin_settings.html', settings=settings, now=datetime.now())

@app.route('/uploads/<filename>')
def uploaded_file(filename):
    safe_filename = secure_filename(filename)
    return send_from_directory(app.config['UPLOAD_FOLDER'], safe_filename)

if __name__ == '__main__':
    port = int(os.environ.get('PORT', 10000))
    app.run(debug=False, host='0.0.0.0', port=port)
