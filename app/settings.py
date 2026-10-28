from flask import Blueprint, flash, g, redirect, render_template, url_for

from security.passwords import check_password, hash_password, password_problem

from .auth import current_account, login_required, password_limit
from .db import get_db
from .duress import DECOY, WIPE, empty_slot, seal_mode
from .forms import DuressForm, RemoveDuressForm, first_error

bp = Blueprint("settings", __name__, url_prefix="/auth")

DECOY_REFUSAL = "The duress password could not be saved. Try again later."


@bp.route("/duress", methods=("GET", "POST"))
@login_required
@password_limit(current_account)
def duress():
    """Set or replace the duress password.

    The page never says whether one is set, so someone who forced the real
    password out of the user learns nothing here either.
    """
    form = DuressForm()
    if form.is_submitted() and g.duress:
        flash(DECOY_REFUSAL)
    elif form.validate_on_submit():
        user = g.user
        problem = password_problem(user["username"], form.duress_password.data)
        if not check_password(user["password_hash"], form.password.data):
            g.wrong_password = True
            flash("Wrong password.")
        elif form.duress_password.data == form.password.data:
            flash("The duress password must be different from your password.")
        elif problem is not None:
            flash(problem)
        else:
            mode = WIPE if form.mode.data == "wipe" else DECOY
            db = get_db()
            duress_hash = hash_password(form.duress_password.data)
            db.execute(
                "UPDATE users SET duress_hash = ?, duress_policy = ? WHERE id = ?",
                (duress_hash, seal_mode(user["username"], mode), user["id"]),
            )
            db.commit()
            # not logged: the audit log must not show who has a duress password
            flash("Duress password saved.", "success")
            return redirect(url_for("settings.duress"))
    elif form.is_submitted():
        flash(first_error(form))
    return render_template("auth/duress.html")


@bp.route("/duress/remove", methods=("POST",))
@login_required
@password_limit(current_account)
def remove_duress():
    form = RemoveDuressForm()
    if g.duress:
        flash(DECOY_REFUSAL)
    elif not form.validate():
        flash(first_error(form))
    elif not check_password(g.user["password_hash"], form.password.data):
        g.wrong_password = True
        flash("Wrong password.")
    else:
        db = get_db()
        db.execute(
            "UPDATE users SET duress_hash = ?, duress_policy = ? WHERE id = ?",
            (*empty_slot(g.user["username"]), g.user["id"]),
        )
        db.commit()
        flash("Duress password removed, if there was one.", "success")
    return redirect(url_for("settings.duress"))
