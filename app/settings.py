import re

from flask import (
    Blueprint,
    abort,
    current_app,
    flash,
    g,
    redirect,
    render_template,
    request,
    url_for,
)

from security.passwords import password_problem

from . import levels
from .audit import audit
from .auth import current_account, login_required, password_limit, password_ok
from .files import keep_private_copies
from .forms import (
    ChangePasswordForm,
    CoverForm,
    DuressForm,
    RemoveDuressForm,
    ReviewForm,
    first_error,
)
from .invites import plural, to_local

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
    return duress_page()


def duress_page():
    # not "here": base.html already names the current page so
    own_files, cover_files = levels.cover_lists()
    changed = levels.cover_changed()
    return render_template(
        "auth/duress.html",
        delay=delay(),
        own_files=own_files,
        cover_files=cover_files,
        changed=f"{changed[:16]} UTC" if changed else "never",
    )


FILE_ID = re.compile(r"[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}")


@bp.route("/duress/cover", methods=("POST",))
@login_required
@password_limit(current_account)
def cover():
    """Move files to the cover files, which the duress password opens, or
    back. Not logged, for the same reason as setting the duress password."""
    form = CoverForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("settings.duress"))
    keys = levels.unlock(form.password.data)
    if keys is None:
        g.wrong_password = True
        flash("Wrong password.")
        return redirect(url_for("settings.duress"))
    ids = [i for i in request.form.getlist("file") if FILE_ID.fullmatch(i)][:500]
    moved = levels.move_files(keys, ids, form.direction.data == "down")
    flash(f"Moved {plural(moved, 'file')}.", "success")
    return redirect(url_for("settings.duress"))


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


@bp.route("/review")
@login_required
def review():
    """What happened while a duress password was in use. Every login with
    the password whose login closed the window comes here, and its other
    sessions link here, until the owner says done."""
    data = levels.review()
    if data is None:
        return redirect(url_for("files.index"))
    return render_template(
        "auth/review.html", since_local=to_local(data["since"]), delay=delay(), **data
    )


@bp.route("/review/<action>", methods=("POST",))
@login_required
@password_limit(current_account)
def review_action(action):
    if action not in ("copy", "restore", "label", "delete", "move", "put-back", "done"):
        abort(404)
    form = ReviewForm()
    if not form.validate():
        flash(first_error(form))
        return redirect(url_for("settings.review"))
    keys = levels.unlock(form.password.data)
    if keys is None:
        g.wrong_password = True
        flash("Wrong password.")
        return redirect(url_for("settings.review"))
    ids = [i for i in request.form.getlist("file") if FILE_ID.fullmatch(i)][:500]
    if action == "copy":
        kept, problems = keep_private_copies(keys, ids)
        flash(f"Saved a private copy of {plural(kept, 'file')}.", "success")
        if problems:
            flash("Not copied: " + "; ".join(p.rstrip(".") for p in problems) + ".")
    elif action == "restore":
        flash(f"Restored {plural(levels.restore(ids), 'file')}.", "success")
    elif action == "label":
        flash(f"Labelled {plural(levels.label(ids), 'file')} for you only.", "success")
    elif action == "delete":
        flash(f"Deleted {plural(levels.remove_planted(ids), 'file')}.", "success")
    elif action == "move":
        flash(f"Moved {plural(levels.bring_back(keys, ids), 'file')}.", "success")
    elif action == "put-back":
        flash(f"Put back {plural(levels.put_back(keys, ids), 'file')}.", "success")
    else:
        leftover = request.form.get("leftover")
        if leftover not in ("restore", "let-go"):
            flash("Choose what happens to what is left.")
            return redirect(url_for("settings.review"))
        levels.review_done(keys, leftover)
        flash("Review done.", "success")
        return redirect(url_for("files.index"))
    return redirect(url_for("settings.review"))


@bp.route("/password", methods=("GET", "POST"))
@login_required
@password_limit(current_account)
def password():
    """Change the password the session logged in with. It locks that
    password's key again, so every file still opens, and ends the other
    sessions it opened."""
    form = ChangePasswordForm(g.user["username"].partition("#")[0])
    if form.validate_on_submit():
        keys = levels.unlock(form.password.data)
        if keys is None:
            g.wrong_password = True
            flash("Wrong password.")
        elif form.new_password.data == form.password.data:
            flash("The new password must be different from your password.")
        elif levels.opens_below(form.new_password.data):
            flash("Choose a password other than your duress password.")
        else:
            levels.change_password(keys, form.new_password.data)
            audit("password", "changed")
            flash("Password changed. Your other sessions have ended.", "success")
            return redirect(url_for("settings.password"))
    elif form.is_submitted():
        flash(first_error(form))
    return render_template("auth/password.html")
