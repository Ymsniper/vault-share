from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import BooleanField, HiddenField, PasswordField, RadioField, StringField, TextAreaField
from wtforms.validators import DataRequired, Length, Regexp, ValidationError

from security.passwords import password_problem

# Flask-WTF also checks the CSRF token of every form below.


class RegisterForm(FlaskForm):
    username = StringField(
        validators=[
            Regexp(
                r"^[A-Za-z0-9_]{3,32}$",
                message="Username must be 3 to 32 letters, digits or underscores.",
            )
        ]
    )
    password = PasswordField(
        validators=[Length(12, 128, message="Password must be 12 to 128 characters long.")]
    )

    def validate_password(self, field):
        if field.errors:  # already refused for its length
            return
        problem = password_problem(self.username.data or "", field.data or "")
        if problem is not None:
            raise ValidationError(problem)


class CodeForm(FlaskForm):
    code = StringField(validators=[Regexp(r"^\d{6}$", message="Type the 6-digit code.")])


class TotpForm(CodeForm):
    password = PasswordField(validators=[DataRequired("Type your password.")])


class DuressForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password.")])
    duress_password = PasswordField(
        validators=[
            Length(12, 128, message="The duress password must be 12 to 128 characters long.")
        ]
    )
    mode = RadioField(choices=["decoy", "wipe"], default="decoy")
    confirm_wipe = BooleanField()

    def validate_confirm_wipe(self, field):
        if self.mode.data == "wipe" and not field.data:
            raise ValidationError("Tick the box to confirm the wipe: it cannot be undone.")


class RemoveDuressForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password.")])


class UnlockForm(FlaskForm):
    passphrase = PasswordField(validators=[DataRequired("Type the passphrase.")])


class LoginForm(FlaskForm):
    username = StringField(validators=[DataRequired()])
    password = PasswordField(validators=[DataRequired()])


class UploadForm(FlaskForm):
    file = FileField(validators=[FileRequired("Choose a file to upload.")])
    description = TextAreaField(
        validators=[Length(max=1000, message="The description is limited to 1000 characters.")]
    )
    password = PasswordField(validators=[DataRequired("Type your password to sign the file.")])


class CheckCopyForm(FlaskForm):
    copy = FileField(validators=[FileRequired("Choose your local copy of the file.")])


class SearchForm(FlaskForm):
    q = StringField(validators=[Length(max=255)])


class ShareForm(FlaskForm):
    username = StringField(validators=[DataRequired("Type a username."), Length(max=32)])


class RevokeForm(FlaskForm):
    recipient_id = HiddenField(validators=[Regexp(r"^\d+$")])


def first_error(form):
    """The first message of the first field that failed, to show the user."""
    for messages in form.errors.values():
        if messages:
            return messages[0]
    return None
