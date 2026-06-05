import sys
sys.path.insert(0, r'D:\研究生毕设\systemwire2')
from flask_server import create_app
app = create_app()
c = app.test_client()
with app.app_context():
    from flask_server.models import User
    u = User.query.filter_by(username='admin').first()
    uid = str(u.id if u else 1)
with c.session_transaction() as sess:
    sess['_user_id'] = uid
    sess['_fresh'] = True
r1 = c.get('/manage/alert/account?days=30')
txt1 = r1.get_data(as_text=True)
r2 = c.get('/manage/alert/unified')
txt2 = r2.get_data(as_text=True)
print('ACCOUNT_ROUTE_STATUS', r1.status_code)
print('UNIFIED_ROUTE_STATUS', r2.status_code)
print('ACCOUNT_HAS_TITLE', ('账户告警记录' in txt1))
print('ACCOUNT_HAS_USERNAME', ('admin' in txt1))
print('UNIFIED_HAS_ACCOUNT_MENU', ('账户告警' in txt2))
print('UNIFIED_HAS_ACCOUNT_FILTER', ('value="account"' in txt2))
