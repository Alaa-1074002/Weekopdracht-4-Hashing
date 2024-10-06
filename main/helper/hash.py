import bcrypt
def hash_password(password):
    # salt
    salt = bcrypt.gensalt()
    hashed_password = bcrypt.hashpw(password.encode(), salt)
    return hashed_password

def verify_password(stored_password, provided_password):
    
    if isinstance(stored_password, str):
        stored_password = stored_password.encode()
    return bcrypt.checkpw(provided_password.encode(), stored_password)