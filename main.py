from website import create_app

app = create_app()  # initializes the flask app

# ensures the server only runs when the script is executed directly
if __name__ == "__main__":
    app.run(debug=True)
