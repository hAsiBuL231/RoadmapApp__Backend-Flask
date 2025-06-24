from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///roadmap.db"  # PostgreSQL/MySQL for production
app.config["JWT_SECRET_KEY"] = "#&hasibul@1516&#"  # strong secret key
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])  # Allowing local origin (for development only)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)

class RoadmapItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    status = db.Column(db.String(50), nullable=False)
    upvotes = db.Column(db.Integer, default=0)

class Upvote(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("roadmap_item.id"), nullable=False)
    __table_args__ = (
        db.UniqueConstraint("user_id", "item_id", name="unique_user_upvote"),
    )

class Comment(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    item_id = db.Column(db.Integer, db.ForeignKey("roadmap_item.id"), nullable=False)
    text = db.Column(db.String(300), nullable=False)  # Max 300 characters
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)
    replies = db.relationship("Reply", backref="comment", cascade="all, delete")

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("comment.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    text = db.Column(db.String(300), nullable=False)
    depth = db.Column(db.Integer, default=1)  # Limit nesting to 3 levels
    timestamp = db.Column(db.DateTime, default=datetime.utcnow)


# Createing the database before running
with app.app_context():
    db.create_all()

@app.route("/")
def home():
    return {"message": "Backend is running!"}


########################################################################################
############################         AUTH SECTION        ###############################
########################################################################################

@app.route("/auth/register", methods=["POST"])
def register():
    data = request.get_json()
    hashed_password = bcrypt.generate_password_hash(data["password"]).decode("utf-8")
    new_user = User(email=data["email"], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({"message": "User registered successfully!"}), 201

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()
    if user and bcrypt.check_password_hash(user.password, data["password"]):
        # access_token = create_access_token(identity=user.id)
        access_token = create_access_token(identity=str(user.id))  # Ensure string
        return jsonify({"access_token": access_token}), 200
    return jsonify({"message": "Invalid credentials"}), 401


@app.route("/dashboard", methods=["GET"])
@jwt_required()
def dashboard():
    current_user = get_jwt_identity()
    return jsonify({"message": f"Welcome, user {current_user}!"})


########################################################################################
###########################    ROADMAP & UPVOTE SECTION   ##############################
########################################################################################

@app.route("/roadmap", methods=["GET"])
def get_roadmap():
    roadmap_items = RoadmapItem.query.all()
    return jsonify([{"id": item.id, "title": item.title, "status": item.status, "upvotes": item.upvotes} for item in roadmap_items])


@app.route("/upvote/<int:item_id>", methods=["POST"])
@jwt_required()
def upvote(item_id):
    print("Request headers:", request.headers)  # Debug: Check headers
    print("Request JSON:", request.json)       # Debug: Check body

    current_user_id = get_jwt_identity()
    item = RoadmapItem.query.get(item_id)
    if not item:
        return jsonify({"message": "Item not found"}), 404

    already_voted = Upvote.query.filter_by(user_id=current_user_id, item_id=item_id).first()
    if already_voted:
        return jsonify({"message": "You’ve already upvoted this item."}), 400

    new_vote = Upvote(user_id=current_user_id, item_id=item_id)
    item.upvotes += 1
    db.session.add(new_vote)
    db.session.commit()

    return jsonify({"message": "Upvote recorded", "item_id": item.id, "total_upvotes": item.upvotes}), 200


########################################################################################
############################   COMMENT & REPLY SECTION   ###############################
########################################################################################

@app.route("/comments/<int:item_id>", methods=["GET"])
def get_comments(item_id):
    comments = Comment.query.filter_by(item_id=item_id).order_by(Comment.timestamp.desc()).all()
    result = []
    for comment in comments:
        replies = [
            {"id": r.id, "text": r.text, "user_id": r.user_id, "depth": r.depth}
            for r in comment.replies
        ]
        result.append({
            "id": comment.id,
            "text": comment.text,
            "user_id": comment.user_id,
            "replies": replies
        })
    return jsonify(result)


@app.route("/comment", methods=["POST"])
@jwt_required()
def add_comment():
    data = request.get_json()
    new_comment = Comment(
        user_id=get_jwt_identity(),
        item_id=data["item_id"],
        text=data["text"]
    )
    db.session.add(new_comment)
    db.session.commit()
    return jsonify({"message": "Comment added successfully!"})

@app.route("/reply", methods=["POST"])
@jwt_required()
def add_reply():
    data = request.get_json()
    depth = data.get("depth", 1)
    if depth > 3:
        return jsonify({"message": "Maximum reply depth reached."}), 400

    new_reply = Reply(
        comment_id=data["comment_id"],
        user_id=get_jwt_identity(),
        text=data["text"],
        depth=depth
    )
    db.session.add(new_reply)
    db.session.commit()
    return jsonify({"message": "Reply added successfully!"})


if __name__ == "__main__":
    app.run(debug=True)