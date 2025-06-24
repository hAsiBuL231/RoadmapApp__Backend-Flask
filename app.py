from flask import Flask, request, jsonify
from flask_sqlalchemy import SQLAlchemy
from flask_bcrypt import Bcrypt
from flask_jwt_extended import JWTManager, create_access_token, jwt_required, get_jwt_identity
from flask_cors import CORS
from datetime import datetime

# pip install -r requirements.txt
# venv\Scripts\activate
# python app.py

app = Flask(__name__)
app.config["SQLALCHEMY_DATABASE_URI"] = "sqlite:///roadmap.db"  # PostgreSQL/MySQL for production
app.config["JWT_SECRET_KEY"] = "#&hasibul@1516&#"  # strong secret key
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False  # Disable track modifications to save resources
app.config["CORS_HEADERS"] = "Content-Type"  # Allow CORS headers
db = SQLAlchemy(app)
bcrypt = Bcrypt(app)
jwt = JWTManager(app)
CORS(app, supports_credentials=True, origins=["http://localhost:3000"])  # Allowing local origin (for development only)


class User(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    email = db.Column(db.String(100), unique=True, nullable=False)
    password = db.Column(db.String(200), nullable=False)
    name = db.Column(db.String(100), nullable=False, default="Anonymous")
    avatar = db.Column(db.String(200), default="/default-avatar.png")

class RoadmapItem(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    title = db.Column(db.String(200), nullable=False)
    description = db.Column(db.Text)
    status = db.Column(db.String(50), nullable=False)
    upvotes = db.Column(db.Integer, default=0)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    comments = db.relationship("Comment", backref="item", cascade="all, delete")

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
    text = db.Column(db.String(500), nullable=False)  # Increased from 300 to 500
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    replies = db.relationship("Reply", backref="parent_comment", cascade="all, delete")
    user = db.relationship("User", backref="comments")

class Reply(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    comment_id = db.Column(db.Integer, db.ForeignKey("comment.id"), nullable=False)
    user_id = db.Column(db.Integer, db.ForeignKey("user.id"), nullable=False)
    text = db.Column(db.String(500), nullable=False)
    depth = db.Column(db.Integer, default=1)
    created_at = db.Column(db.DateTime, default=datetime.utcnow)
    updated_at = db.Column(db.DateTime, onupdate=datetime.utcnow)
    user = db.relationship("User", backref="replies")


# Create database tables
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
    new_user = User(
        email=data["email"],
        password=hashed_password,
        name=data.get("name", "Anonymous"),
        avatar=data.get("avatar", "/default-avatar.png")
    )
    db.session.add(new_user)
    db.session.commit()
    access_token = create_access_token(identity=str(new_user.id))
    return jsonify({
        "message": "User registered successfully!",
        "user": {
            "id": new_user.id,
            "name": new_user.name,
            "avatar": new_user.avatar
        },
        "access_token": access_token
    }), 201

@app.route("/auth/login", methods=["POST"])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data["email"]).first()
    if user and bcrypt.check_password_hash(user.password, data["password"]):
        access_token = create_access_token(identity=str(user.id))
        return jsonify({
            "access_token": access_token,
            "user": {
                "id": user.id,
                "name": user.name,
                "avatar": user.avatar
            }
        }), 200
    return jsonify({"message": "Invalid credentials"}), 401

@app.route("/auth/me", methods=["GET"])
@jwt_required()
def get_current_user():
    user_id = get_jwt_identity()
    user = User.query.get(user_id)
    if not user:
        return jsonify({"message": "User not found"}), 404
    return jsonify({
        "id": user.id,
        "name": user.name,
        "email": user.email,
        "avatar": user.avatar
    })


########################################################################################
###########################    ROADMAP & UPVOTE SECTION   ##############################
########################################################################################

@app.route("/roadmap", methods=["GET"])
def get_roadmap():
    status = request.args.get("status", "all")
    search = request.args.get("search", "")
    
    query = RoadmapItem.query
    
    if status != "all":
        query = query.filter_by(status=status)
    
    if search:
        query = query.filter(
            (RoadmapItem.title.ilike(f"%{search}%")) | 
            (RoadmapItem.description.ilike(f"%{search}%"))
        )

    roadmap_items = query.order_by(RoadmapItem.created_at.desc()).all()
    
    return jsonify([{
        "id": item.id,
        "title": item.title,
        "description": item.description,
        "status": item.status,
        "upvotes": item.upvotes,
        "createdAt": item.created_at.isoformat(),
        "commentCount": len(item.comments)
    } for item in roadmap_items])

@app.route("/upvote/<int:item_id>", methods=["POST"])
@jwt_required()
def upvote(item_id):
    current_user_id = get_jwt_identity()
    item = RoadmapItem.query.get(item_id)
    if not item:
        return jsonify({"message": "Item not found"}), 404

    already_voted = Upvote.query.filter_by(user_id=current_user_id, item_id=item_id).first()
    if already_voted:
        return jsonify({"message": "You've already upvoted this item."}), 400

    new_vote = Upvote(user_id=current_user_id, item_id=item_id)
    item.upvotes += 1
    db.session.add(new_vote)
    db.session.commit()

    return jsonify({
        "message": "Upvote recorded",
        "item_id": item.id,
        "total_upvotes": item.upvotes,
        "hasUpvoted": True
    }), 200


########################################################################################
#############################      COMMENT SECTION      ################################
########################################################################################

@app.route("/comments/<int:item_id>", methods=["GET"])
def get_comments(item_id):
    comments = Comment.query.filter_by(item_id=item_id).order_by(Comment.created_at.desc()).all()
    
    def build_comment_tree(comment):
        replies = Reply.query.filter_by(comment_id=comment.id).order_by(Reply.created_at.asc()).all()
        return {
            "id": comment.id,
            "text": comment.text,
            "userId": comment.user_id,
            "user": {
                "id": comment.user.id,
                "name": comment.user.name,
                "avatar": comment.user.avatar
            },
            "createdAt": comment.created_at.isoformat(),
            "updatedAt": comment.updated_at.isoformat() if comment.updated_at else None,
            "replies": [{
                "id": reply.id,
                "text": reply.text,
                "userId": reply.user_id,
                "user": {
                    "id": reply.user.id,
                    "name": reply.user.name,
                    "avatar": reply.user.avatar
                },
                "depth": reply.depth,
                "createdAt": reply.created_at.isoformat(),
                "updatedAt": reply.updated_at.isoformat() if reply.updated_at else None
            } for reply in replies]
        }
    
    return jsonify([build_comment_tree(comment) for comment in comments])

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
    
    # Return the full comment with user data
    comment = Comment.query.get(new_comment.id)
    return jsonify({
        "id": comment.id,
        "text": comment.text,
        "userId": comment.user_id,
        "user": {
            "id": comment.user.id,
            "name": comment.user.name,
            "avatar": comment.user.avatar
        },
        "createdAt": comment.created_at.isoformat(),
        "replies": []
    }), 201

@app.route("/comments/<int:comment_id>", methods=["PUT", "DELETE"])
@jwt_required()
def handle_comment(comment_id):
    comment = Comment.query.get(comment_id)
    if not comment:
        return jsonify({"message": "Comment not found"}), 404
    
    current_user_id = get_jwt_identity()
    if comment.user_id != current_user_id:
        return jsonify({"message": "Unauthorized"}), 403
    
    if request.method == "PUT":
        data = request.get_json()
        comment.text = data["text"]
        comment.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({
            "id": comment.id,
            "text": comment.text,
            "updatedAt": comment.updated_at.isoformat()
        })
    
    elif request.method == "DELETE":
        db.session.delete(comment)
        db.session.commit()
        return jsonify({"message": "Comment deleted successfully"})

########################################################################################
#############################       REPLY SECTION       ################################
########################################################################################

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
    
    # Return the full reply with user data
    reply = Reply.query.get(new_reply.id)
    return jsonify({
        "id": reply.id,
        "text": reply.text,
        "userId": reply.user_id,
        "user": {
            "id": reply.user.id,
            "name": reply.user.name,
            "avatar": reply.user.avatar
        },
        "depth": reply.depth,
        "createdAt": reply.created_at.isoformat()
    }), 201

@app.route("/replies/<int:reply_id>", methods=["PUT", "DELETE"])
@jwt_required()
def handle_reply(reply_id):
    reply = Reply.query.get(reply_id)
    if not reply:
        return jsonify({"message": "Reply not found"}), 404
    
    current_user_id = get_jwt_identity()
    if reply.user_id != current_user_id:
        return jsonify({"message": "Unauthorized"}), 403
    
    if request.method == "PUT":
        data = request.get_json()
        reply.text = data["text"]
        reply.updated_at = datetime.utcnow()
        db.session.commit()
        return jsonify({
            "id": reply.id,
            "text": reply.text,
            "updatedAt": reply.updated_at.isoformat()
        })
    
    elif request.method == "DELETE":
        db.session.delete(reply)
        db.session.commit()
        return jsonify({"message": "Reply deleted successfully"})


if __name__ == "__main__":
    app.run(debug=True)