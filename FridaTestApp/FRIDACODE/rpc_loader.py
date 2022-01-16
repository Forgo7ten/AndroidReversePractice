import time
import frida


## handler | script脚本信息交互函数
def my_message_handler(message, payload):
    print(message)  # 打印得到的信息
    print(payload)  # 输出的为`none`?
    # 如果`type`字段为"send" 则是js发来的消息
    if message["type"] == "send":
        # 打印json的`payload`内容(js发送过来的内容)
        print(message["payload"])
        # 向script发送消息，格式为字典
        script.post({"my_data": "Hello"})


# 通过Usb连接设备
# device = frida.get_usb_device()

# 通过ip:port 连接设备
device = frida.get_device_manager().add_remote_device("192.168.0.104:8888")
################ 通过spawn方式启动 ###########################
pid = device.spawn(["com.forgotten.fridatestapp"])
device.resume(pid)
time.sleep(1)
session = device.attach(pid)
##### <<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<<
# session = device.attach("com.forgotten.fridatestapp")
################ 通过attach现有进程方式启动 ###################
with open("./frida_rpc.js") as f:
    # 创建一个新脚本
    script = session.create_script(f.read())
# 加载信息交互handler函数
script.on("message", my_message_handler)
# 加载脚本
script.load()

command = ""
while True:
    command = input("Enter `n` for leave: ")
    if command == "n":
        break
