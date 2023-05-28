### 系統環境
EC2 + NGINX + UWSGI + git action

### 常用套件
`flask_migrate`：這個套件用在資料庫遷移，它提供了命令行工具和函式庫，讓你可以管理資料庫的版本和遷移。
`flask_restful`：這個套件在 Flask 中構建 RESTful API 比較快，可以很快定義資源和路由，處理請求和回應，以及處理驗證和授權等相關功能。
`flask_sqlalchemy`：這個套件是 Flask 的 SQLAlchemny 擴充套件，提供了對關聯式資料庫的支援。可以幫助定義資料庫模型、執行資料庫操作。

### 專案結構
```
Flask專案
├─ apps
│  ├─ __init__.py
│  ├─ Modules.py
│  └─ simple_app
│     ├─ __init__.py
│     ├─ views.py
│     └─ def_simple_app.py
│
├─ models
│  ├─ __init__.py
│  ├─ ORM Model 1.py
│  ├─ ORM Model 2.py
│  └─ ...
│
├─ config.py
└─ manage.py
```

- `apps` 資料夾：這個資料夾包含了應用程式的相關檔案。
  - `__init__.py`：這個檔案是一個空的 __init__ 模組，主要用於註冊應用程式。
  - `Modules.py`：這個檔案是套件管理模組，用於管理所有的套件。
  - `simple_app` 資料夾：就依app功能命名，例如user之類的
    - `views.py`：主要負責定義 URL 路由。
    - `def_views.py`：主要撰寫各個 API 的邏輯，可能包括數據處理、資料庫操作、驗證和授權等。
- `models` 資料夾：這個資料夾包含了各個 ORM Model 的撰寫。
  - `__init__.py`：主要用來初始化資料庫。
  - `ORM Model 1.py`：這個檔案用來定義 ORM Model，你可以有多個類似的檔案用於不同的 Model  (會使用到 flask_sqlalchemy 套件提供的功能)。
- `config.py`：這個檔案包含了 Flask 相關的設定，例如資料庫連接等。
- `manage.py`：這個檔案主要用於初始化和啟動整個專案，例如設定 Flask App 實例、運行開發伺服器等。
```
# manage.py
from app import create_app, db
from models.admin import *
from models.member import *
from app.Modules import *
from models import init_db

app = create_app('default')
CORS(app)
manager = Migrate(app, db)
login_manager = LoginManager()
login_manager.init_app(app)

@app.before_request
def func():
    session.permanent = True
    app.permanent_session_lifetime = timedelta(days=1)

@login_manager.user_loader
def load_user(user_id):
    if user_id.startswith('A'):
        return Admin.query.filter_by(id=user_id[1:]).first()
    elif user_id.startswith('M'):
        return Member.query.filter_by(id=user_id[1:]).first()

if __name__ == '__main__':
    with app.app_context():
        init_db()
        db.create_all()
    print(app.url_map)
    app.run('0.0.0.0', port=5002, debug=True)
```