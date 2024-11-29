from app import db, bcrypt


from sqlalchemy import String


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    username = db.Column(db.String(150), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)  # Use 200 to fit hashes
    role = db.Column(db.String(50), nullable=False, default='user')  # 'admin' or 'user'

    def __repr__(self):
        return f'<User {self.username}>'

    @staticmethod
    def create_user(username, password):
        hashed_password = bcrypt.generate_password_hash(password).decode('utf-8')
        return User(username=username, password=hashed_password)


class MenuItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    name = db.Column(db.String(100), nullable=False)
    price = db.Column(db.Float, nullable=False)


class Order(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    item_id = db.Column(db.Integer, db.ForeignKey('menu_item.id'), nullable=False)
    quantity = db.Column(db.Integer, nullable=False)
    total_price = db.Column(db.Float, nullable=False)

    item = db.relationship('MenuItem', backref='orders')
