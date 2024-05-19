import subprocess

# 编译Go文件
cmd = ['go', 'build', 'main.go']
subprocess.run(cmd)

# 执行可执行文件
cmd = ['./main']
subprocess.run(cmd)


