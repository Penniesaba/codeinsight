import os

def process_user_input(user_input):
    # 获取当前目录
    current_dir = os.getcwd()
    
    # 用户输入分割处理
    parts = user_input.split()
    
    # 不安全：将环境数据与用户输入拼接作为命令执行
    if parts and parts[0] == "list":
        # 构造命令
        command = "ls -la " + current_dir + "/" + parts[1]
        
        # 执行命令
        os.system(command)  # 这里存在命令注入漏洞
        
def main():
    while True:
        user_input = input("请输入命令 (例如 'list temp'): ")
        if user_input.lower() == "exit":
            break
            
        process_user_input(user_input)

if __name__ == "__main__":
    main() 