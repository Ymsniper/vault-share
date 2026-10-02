from app import create_app

app = create_app()

if __name__ == "__main__":
    if app.config["HTTPS"]:
        app.run(ssl_context=(app.config["TLS_CERT"], app.config["TLS_KEY"]))
    else:
        app.run()
