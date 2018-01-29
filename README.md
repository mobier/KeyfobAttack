#汽车遥控常用加解密算法
## 接收到的数据
>keeloq C代码 运算秘钥
>滚动码数据:861ae518,9003f427,a2f9521b
>序列号:39182da

-------
#### 标准算法解密密文
```
key=0x0000000000000000; //厂商KEY
gcc Standard_Keeloq_Decrypt.c -o Standard_Keeloq_Decrypt
./Standard_Keeloq_Decrypt 39182da 861ae518
42DA4BFA//明文数据
```
#### 标准秘钥创建解码秘钥
```
key=0x0000000000000000; //厂商KEY
gcc Create_keeloq_key.c -o Create_key
./Create_key 39182da//序列号
7D093B66B31C374A //编码KEY
```
#### 解密Keeloq 密文
```
key=0x7D093B66B31C374A; //编码KEY
./Keeloq_Decrypt a2f9521b
42DA4BFF//明文
```
#### 加密Keeloq 密文
```
key=0x7D093B66B31C374A; //编码KEY
./Keeloq_Encrypt 42DA4BFF
A2F9521B//密文
```

---------
# hitag 2
## ........
