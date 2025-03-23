import os

class Config:
    SECRET_KEY = os.environ.get('SECRET_KEY') or 'your_secret_key'  # Important for session management!
    UPLOAD_FOLDER = os.path.join('static', 'profile_images') # Path where you upload the images
    MAX_CONTENT_LENGTH = 16 * 1024 * 1024  # 16MB max size