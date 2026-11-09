from flask import Blueprint, current_app, flash, g, redirect, render_template, url_for

from security.passwords import password_problem

from . import levels
from .auth import current_account, login_required, password_limit, password_ok
from .forms import DuressForm, RemoveDuressForm, first_error
from .invites import plural

bp = Blueprint("settings", __name__, url_prefix="/auth")


@bp.route("/duress", methods=("GET", "POST"))
@login_required
@password_limit(current_account)
def duress():
    """Set or replace the duress password.

    It opens a vault of its own, the cover files, kept under keys the real
    password reaches and the duress password never climbs out of. Every
    session sets the duress password of the vault below its own, so the
    page works, and looks, the same in each. It never says whether one is
    set, so someone who forced a password out of the user learns nothing
    here either.
    """
    form = DuressForm()
    if form.validate_on_submit():
        problem = password_problem(g.user["username"], form.duress_password.data)
        keys = levels.unlock(form.password.data)
        if keys is None:
            g.wrong_password = True
            flash("Wrong password.")
        elif form.duress_password.data == form.password.data:
            flash("The duress password must be different from your password.")
        elif problem is not None:
            flash(problem)
        else:
            levels.set_duress(keys, form.duress_password.data, form.mode.data)
            # not logged: the audit log must not show who has a duress password
            flash(f"Duress password saved. It becomes active in {delay()}.", "success")
            return redirect(url_for("settings.duress"))
    elif form.is_submitted():
        flash(first_error(form))
    return render_template("auth/duress.html", delay=delay())


def delay():
    """How long a new duress password waits before it works, for the page."""
    return plural(current_app.config["DURESS_DELAY"] // 3600, "hour")


@bp.route("/duress/remove", methods=("POST",))
@login_required
@password_limit(current_account)
def remove_duress():
    form = RemoveDuressForm()
    if not form.validate():
        flash(first_error(form))
    elif not password_ok(form.password.data):
        g.wrong_password = True
        flash("Wrong password.")
    else:
        # the cover files stay, under the keys the real password reaches
        levels.remove_duress()
        flash("Duress password removed, if there was one.", "success")
    return redirect(url_for("settings.duress"))
