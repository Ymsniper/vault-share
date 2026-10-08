from app import create_app

app = create_app()

if __name__ == "__main__":
    # locks the app within a second of the key USB stick being pulled out
    app.extensions["keyring"].watch(app)
    if app.config["HTTPS"]:
        app.run(ssl_context=(app.config["TLS_CERT"], app.config["TLS_KEY"]))
    else:
        app.run()
