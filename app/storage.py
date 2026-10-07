import os

from flask import current_app


def storage_path(file_id):
    # the name on disk is the random file ID, never anything the client sent
    return os.path.join(current_app.config["STORAGE_FOLDER"], file_id)
