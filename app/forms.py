from flask_wtf import FlaskForm
from flask_wtf.file import FileField, FileRequired
from wtforms import BooleanField, PasswordField, RadioField, StringField, TextAreaField
from wtforms.validators import AnyOf, DataRequired, Length, Regexp, ValidationError

from security.passwords import password_problem

# Flask-WTF also checks the CSRF token of every form below.


class RegisterForm(FlaskForm):
    code = StringField(validators=[DataRequired("Type your invite code."), Length(max=40)])
    # no "#": the server adds "#" and the tag after the name
    username = StringField(
        validators=[
            Regexp(
                r"^[A-Za-z0-9_]{3,32}$",
                message="Username must be 3 to 32 letters, digits or underscores.",
            )
        ]
    )


class NewPasswordForm(FlaskForm):
    password = PasswordField(
        validators=[Length(12, 128, message="Password must be 12 to 128 characters long.")]
    )

    def __init__(self, chosen_name, *args, **kwargs):
        super().__init__(*args, **kwargs)
        self.chosen_name = chosen_name

    def validate_password(self, field):
        if field.errors:  # already refused for its length
            return
        problem = password_problem(self.chosen_name, field.data or "")
        if problem is not None:
            raise ValidationError(problem)


class CodeForm(FlaskForm):
    code = StringField(validators=[Regexp(r"^\d{6}$", message="Type the 6-digit code.")])


class TotpForm(CodeForm):
    password = PasswordField(validators=[DataRequired("Type your password.")])


class RecoveryForm(FlaskForm):
    recovery = StringField(validators=[DataRequired("Type a recovery code."), Length(max=40)])


class DuressForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password.")])
    duress_password = PasswordField(
        validators=[
            Length(12, 128, message="The duress password must be 12 to 128 characters long.")
        ]
    )
    mode = RadioField(choices=["cover", "wipe"], default="cover")
    confirm_wipe = BooleanField()

    def validate_confirm_wipe(self, field):
        if self.mode.data == "wipe" and not field.data:
            raise ValidationError("Tick the box to confirm the wipe: it cannot be undone.")


class RemoveDuressForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password.")])


class ReviewForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password.")])


class CoverForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password.")])
    # to the cover files, or back from them
    direction = StringField(validators=[AnyOf(["down", "up"])])


class LoginForm(FlaskForm):
    # no real username or password is longer, so these never reach Argon2
    username = StringField(validators=[DataRequired(), Length(max=40)])
    password = PasswordField(validators=[DataRequired(), Length(max=128)])


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


class DownloadForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password to open the file.")])
    # asked of recipients of an archive, which was not checked
    understood = BooleanField()


class ShareForm(FlaskForm):
    # a name, "#" and the 6-digit tag
    username = StringField(validators=[DataRequired("Type a username."), Length(max=40)])
    password = PasswordField(validators=[DataRequired("Type your password to share the file.")])


class RevokeForm(FlaskForm):
    recipient_id = StringField(validators=[Regexp(r"^\d+$")])
    # so a stolen session cookie alone cannot cut anyone off
    password = PasswordField(validators=[DataRequired("Type your password to revoke the share.")])


class DeleteForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password to delete the file.")])


class DismissForm(FlaskForm):
    password = PasswordField(validators=[DataRequired("Type your password to remove the file.")])


def first_error(form):
    """The first message of the first field that failed, to show the user."""
    for messages in form.errors.values():
        if messages:
            return messages[0]
    return None
