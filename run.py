# coding:UTF-8
import os
import sys
from multiprocessing import Process
from app import app
from app.monitor import Monitor
from flask_jwt_extended import JWTManager  

if __name__ == '__main__':
    
    mt = Monitor(os.path.abspath(app.config["UPLOAD_FOLDER"]))
    p_monitor = Process(target=mt.start, args=(0,))
    p_monitor.start()
    jwt = JWTManager(app)
    p_app = Process(target=app.run, kwargs={"host": "0.0.0.0", "port": 8000, "debug": True})
    # app.run(host='0.0.0.0', port=8000, debug=True)
    p_app.start()
    p_monitor.join()
    p_app.join()