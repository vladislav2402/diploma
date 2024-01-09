def allowed_file_names(filename):
    return '.' in filename and filename.rsplit('.', 1)[1].lower() in {'yaml', 'yml'}