import socket
import pickle

def handle_client(client_socket):
    # 从socket接收数据
    data = client_socket.recv(4096)
    
    # 不安全：直接反序列化来自网络的数据
    try:
        obj = pickle.loads(data)  # 这里存在漏洞
        print("接收到对象:", obj)
    except Exception as e:
        print("反序列化错误:", str(e))
    
    client_socket.close()

def start_server():
    server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server.bind(('localhost', 9999))
    server.listen(5)
    print("服务器启动，等待连接...")
    
    while True:
        client, addr = server.accept()
        print(f"接受来自 {addr[0]}:{addr[1]} 的连接")
        handle_client(client)

if __name__ == "__main__":
    start_server() 