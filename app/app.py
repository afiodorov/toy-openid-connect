from http import HTTPStatus
import os
import uuid

from dotenv import load_dotenv
from flask import Flask, request, jsonify, send_from_directory
from flask_migrate import Migrate
from flask_sqlalchemy import SQLAlchemy
from sqlalchemy.dialects.postgresql import UUID
from sqlalchemy.exc import IntegrityError
from werkzeug.security import check_password_hash, generate_password_hash

load_dotenv()

app = Flask(__name__)

db_user = os.environ.get("POSTGRES_USER", "test_user")
db_password = os.environ.get("POSTGRES_PASSWORD", "test_pass")
db_name = os.environ.get("POSTGRES_DB", "test_db")

app.config[
    "SQLALCHEMY_DATABASE_URI"
] = f"postgresql://{db_user}:{db_password}@localhost/{db_name}"
app.config["SQLALCHEMY_TRACK_MODIFICATIONS"] = False

db = SQLAlchemy(app)
migrate = Migrate(app, db)


class Client(db.Model):
    id = db.Column(UUID(as_uuid=True), primary_key=True, default=uuid.uuid4)
    client_secret = db.Column(db.String(128), nullable=False)
    redirect_url = db.Column(db.Text, unique=True, nullable=False)

    def set_client_secret(self, secret: str):
        self.client_secret = generate_password_hash(secret)

    def check_client_secret(self, secret: str) -> bool:
        return check_password_hash(self.client_secret, secret)


@app.route("/clients", methods=["PUT"])
def create_client():
    data = request.get_json()

    new_client = Client(
        client_secret=generate_password_hash(data["client_secret"]),
        redirect_url=data["redirect_url"],
    )

    db.session.add(new_client)

    try:
        db.session.commit()
    except IntegrityError:
        db.session.rollback()

        return jsonify({"error": "already exists"}), HTTPStatus.CONFLICT

    return jsonify({"client_id": new_client.id}), HTTPStatus.CREATED


@app.route("/authorize", methods=["GET"])
def auth():
    client_id = request.args.get("client_id")
    redirect_url = request.args.get("redirect_url")
    response_type = request.args.get("response_type")
    scopes = request.args.get("scopes")

    if not client_id or not redirect_url or not response_type or not scopes:
        return "Missing required query parameters", HTTPStatus.BAD_REQUEST

    client = Client.query.filter_by(id=client_id).first()

    if not client:
        return "Invalid client_id", HTTPStatus.BAD_REQUEST

    if response_type != "code":
        return "Response type not supported", HTTPStatus.BAD_REQUEST

    if client.redirect_url != redirect_url:
        return "Invalid redirect_url", HTTPStatus.BAD_REQUEST

    scopes = scopes.split(" ")
    if "openid" not in scopes:
        return "Not an openid request", HTTPStatus.BAD_REQUEST

    return send_from_directory("static", "auth.html")


if __name__ == "__main__":
    app.run()
