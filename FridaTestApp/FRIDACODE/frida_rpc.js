Java.perform(function () {
    Java.use("com.forgotten.fridatestapp.HookedObject").getPasswd.implementation = function () {
        // 需要发送给python的字符串：由函数的参数和结果拼接而成
        var string_to_send = arguments[0] + ":" + this.getPasswd(arguments[0]);
        var string_to_recv;
        // 发送到python程序
        send(string_to_send);
        // 同时调用.wait()来 阻塞运行，等待接收消息
        recv(function (received_json_objection) {
            // 接收来的json字符串
            console.log("recv in js:",JSON.stringify(received_json_objection))
            // 打印json的`my_data`,json串来自python
            string_to_recv = received_json_objection.my_data;
            console.log("string_to_recv:", string_to_recv);
        }).wait();
        // 将接收到的字符串当作被hook函数的结果返回回去
        var result = Java.use("java.lang.String").$new(string_to_recv);
        return result;
    };
});
