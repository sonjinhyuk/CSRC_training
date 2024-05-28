import os



def create_directory(directory):
    """
        mkdir function
        :param directory str: directory path
        :return None
    """
    try:
        if not os.path.exists(directory):
            os.makedirs(directory)
    except OSError:
        print("Error: Creating directory. " + directory)
        exit()