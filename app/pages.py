"""Pages anyone may read, logged in or not, and while the service is paused
too: they need neither the database nor the master key."""
from flask import Blueprint, current_app, render_template

bp = Blueprint("pages", __name__)

# served before any check that needs the database or the master key
ALWAYS_SERVED = {"static", "pages.security"}


@bp.route("/security")
def security():
    """How this server keeps files and accounts, and what it records. The
    same page for everyone: only the server's own settings fill it in."""
    hours = current_app.config["DURESS_DELAY"] // 3600
    return render_template(
        "security.html",
        log_days=current_app.config["AUDIT_LOG_DAYS"],
        delay=f"{hours} hour" + ("" if hours == 1 else "s"),
    )
