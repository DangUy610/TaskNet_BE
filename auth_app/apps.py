# auth_app/apps.py
from django.apps import AppConfig

class AuthAppConfig(AppConfig):
    name = 'auth_app'

    def ready(self):
        # import signals khi Django khởi động
        import auth_app.signals