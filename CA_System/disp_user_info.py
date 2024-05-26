from peewee import SqliteDatabase, Model, CharField, BigIntegerField

# 定义与数据库表对应的模型类
filename = input("请输入存储用户信息数据文件的路径：")
db = SqliteDatabase(filename)

class User(Model):
    user_id = CharField(unique=True)
    user_name = CharField()
    email = CharField()
    password = CharField()
    public_key = CharField()
    created_time = BigIntegerField()
    status = CharField()

    class Meta:
        database = db

# 连接到数据库并打印所有用户信息
def print_user_info():
    db.connect()
    users = User.select()
    for user in users:
        print(f"User ID: {user.user_id}")
        print(f"User Name: {user.user_name}")
        print(f"Email: {user.email}")
        print(f"Password: {user.password}")
        print(f"Public Key: {user.public_key}")
        print(f"Created Time: {user.created_time}")
        print(f"Status: {user.status}")
        print()

# 调用函数打印用户信息
print_user_info()
