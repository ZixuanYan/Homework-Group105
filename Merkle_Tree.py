import hashlib

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
    print(lst1)
    assert len(lst1) > 2

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


l = ['S', 'D', 'U', 'Y','Z', 'X']
print(concat_and_hash_list(l))
