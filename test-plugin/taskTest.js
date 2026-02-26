let ext = seal.ext.find('taskTest');
if (!ext) {
    ext = seal.ext.new('taskTest', '某人', '1.0.0');
    seal.ext.register(ext);
}

seal.ext.registerTask(ext, "cron", "*/1 * * * * *", (taskCtx) => {
    const now = new Date(taskCtx.now * 1000);
    console.log(`[定时任务] 当前时间：${now.toLocaleString()}`);
}, "timer_every_1s", "每1秒打印一次当前时间的定时任务");
