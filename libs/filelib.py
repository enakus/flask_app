from os import listdir
from os.path import isfile, join

ALLOWED_EXTENSIONS = {'png', 'jpg', 'jpeg', 'gif'}

def get_share_files(path):
	files = [f for f in listdir(path) if isfile(join(path, f))]
	return files

def allowed_file(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in ALLOWED_EXTENSIONS
