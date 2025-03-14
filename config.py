DEBUG = False
WTF_CSRF_ENABLED = False
APP_MODEL_DIR = './app/model/save_model'
SECRET_KEY = '!@#$%8F6F98EC3684AECA1DC44E1CB816E4A5^&*()'
UPLOAD_FOLDER = './store/pcap/'
FILE_FOLDER = './store/files/'
PDF_FOLDER = './store/files/pdf/'
WEB_FLODER = './store/files/Web/'
ALL_FLODER = './store/files/All/'
MAIL_FLODER = './store/files/Mail/'
FTP_FLODER = './store/files/Ftp/'
CSV_FLODER = './store/files/csv/'
FLOWMETER_FLODER = './assets/flowmeter/'
MODEL_DIR = './assets/ML/pickles/'
MODEL_PATH = './assets/ML/pickles/LogReg_1.pkl'
ZIP_PATH = './store/pcap/pcap.zip'
SQLALCHEMY_DATABASE_URI = 'sqlite:///pcap.db'
JWT_SECRET_KEY = 'my_secret_key'
NUM =3

M1_LIMIT =0.75

MODE_3 =['categorical_focal_crossentropy', 0.001, 'Accuracy', 2]
# 恶意加密流量分类
# MODE_3_LOSS = 'categorical_crossentropy'
# # categorical_crossentropy,categorical_focal_crossentropy,
# # categorical_hinge,sparse_categorical_crossentropy
# MODE_3_LEARNINGRATE = 0.001
# MODE_3_METRICS = 'accuracy'
# #Accuracy,CategoricalAccuracy,SparseCategoricalAccuracy
# MODE_3_BATCH = None

MODE_4 =['binary_crossentropy', 0.001, 'Accuracy', 2]
#恶意加密流量识别
# MODE_4_LOSS = 'binary_crossentropy'
# #binary_crossentropy,binary_focal_crossentropy,hinge
# MODE_4_LEARNINGRATE = 0.001
# MODE_4_METRICS = 'accuracy'
# #Accuracy,BinaryAccuracy
# MODE_4_BATCH = None

MODE_5 =['categorical_crossentropy', 0.001, 'Accuracy', 2]
#恶意加密流量类别，加密流量识别
# MODE_5_LOSS = "categorical_crossentropy"
# # categorical_crossentropy,categorical_focal_crossentropy,
# # categorical_hinge,sparse_categorical_crossentropy
# MODE_5_LEARNINGRATE = 0.001
# MODE_5_METRICS = 'accuracy'
# #Accuracy,CategoricalAccuracy,SparseCategoricalAccuracy
# MODE_5_BATCH = None