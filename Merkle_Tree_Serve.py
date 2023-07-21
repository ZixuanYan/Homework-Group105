import hashlib
import socket

def hash_data(data, hash_function='sha256'):
    """对数据进行哈希计算的函数"""
    hash_function = getattr(hashlib, hash_function)
    data = data.encode('utf-8')
    return hash_function(data).hexdigest()

def concat_and_hash_list(lst, hash_function='sha256'):
    """
    根据输入列表生成Merkle树的根哈希值和树的高度

    参数:
    lst -- 输入列表
    hash_function -- 哈希函数名称，默认为'sha256'

    返回值:
    一个包含Merkle树的根哈希值和树的高度的元组
    """
    # 对列表中的每个元素进行哈希计算并存储在lst1列表中
    lst1 = []
    for i in lst:
        lst1.append(hash_data(i))

    assert len(lst1) > 2, "no transactions to be hashed"

    # 迭代地将哈希值进行合并，直到只剩下一个哈希值（树的根哈希值）
    n = 0  # Merkle树的高度
    while len(lst1) > 1:
        n += 1
        if len(lst1) % 2 == 0:
            v = []
            while len(lst1) > 1:
                a = lst1.pop(0)
                b = lst1.pop(0)
                v.append(hash_data(a + b, hash_function))
            lst1 = v
        else:
            v = []
            l = lst1.pop(-1)
            while len(lst1) > 1:
                a = lst1.pop(0)
                b = lst1.pop(0)
                v.append(hash_data(a + b, hash_function))
            v.append(l)
            lst1 = v
    
    # 返回合并完成后的列表以及Merkle树的高度
    return lst1, n + 1


# 服务器端
def server():
    # 创建套接字
    server_socket = socket.socket()
    server_host = 'localhost'  # 服务器主机名
    server_port = 9999  # 服务器端口号

    # 绑定套接字到指定的主机和端口号
    server_socket.bind((server_host, server_port))

    # 开始监听传入的连接请求
    server_socket.listen(1)
    print("服务器正在监听...")

    # 等待客户端连接
    client_socket, addr = server_socket.accept()
    print("与客户端建立连接：", addr)

    # 接收客户端发送的数据
    data = client_socket.recv(1024).decode()
    print("接收到的数据：", data)

    # 根据接收到的数据生成Merkle树
    transactions = data.split(",")
    root_hash, tree_height = concat_and_hash_list(transactions)

    # 发送Merkle树的根哈希值和树的高度给客户端
    response = f"根哈希值：{root_hash[0]}\n树的高度：{tree_height}"
    client_socket.send(response.encode())

    # 关闭连接
    client_socket.close()
    server_socket.close()


# 运行服务器和客户端
if __name__ == '__main__':
    server()

