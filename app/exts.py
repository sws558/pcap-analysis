# 1.导入第三方插件
from flask_sqlalchemy import SQLAlchemy
from flask_migrate import Migrate

# 2. 初始化
db = SQLAlchemy() # ORM
migrate = Migrate() # 数据迁移

# 3. 和app对象绑定
def init_exts(app):
    db.init_app(app=app)
    migrate.init_app(app=app, db=db)