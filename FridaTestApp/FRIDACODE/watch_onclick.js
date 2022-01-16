function watch(obj, mtdName) {
    var listener_name = getObjClassName(obj);
    var target = Java.use(listener_name);
    if (!target || !mtdName in target) {
        return;
    }
    target[mtdName].overloads.forEach(function (overload) {
        overload.implementation = function () {
            console.log("[WatchEvent]" + mtdName + ":" + getObjClassName(this));
            return this[mtdName].apply(this.argument);
        };
    });
}
function OnClickListener() {
    Java.perform(function () {
        // 以spawn的模式自启动的hook
        Java.use("android.view.View").setOnClickListener.implementation = function (listener) {
            if (listener != null) {
                watch(listener, "onClick");
            }
            return this.setOnClickListener(listener);
        };
        // attach模式去附加进程的hook，就是更慢的hook，需要看hook的时机，hook一些已有的东西
        Java.choose("android.view.ViewListenerInfo", {
            onMatch: function (instance) {
                instance = instance.mOnClickListener.value;
                if (instance) {
                    console.log("instance name is" + getObjClassName(instance));
                    watch(instance, "onClick");
                }
            },
            onComplete: function () {},
        });
    });
}

setImmediate(OnClickListener)