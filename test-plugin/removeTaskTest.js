let ext = seal.ext.find('removeTaskTest');
if (!ext) {
    ext = seal.ext.new('removeTaskTest', '某人', '1.0.0');
    seal.ext.register(ext);
}

const getNow = () => {
    const d = new Date();
    return `[${d.getHours().toString().padStart(2, '0')}:${d.getMinutes().toString().padStart(2, '0')}:${d.getSeconds().toString().padStart(2, '0')}]`;
};

console.log(`${getNow()} 测试启动：注册 3 个 once 任务...`);

seal.ext.registerTask(ext, "once", "5000", (ctx) => {
    console.log(`${getNow()} 【错误】任务 A (Key: ${ctx.key}) 竟然执行了！`);
}, "task_A");

seal.ext.registerTask(ext, "once", "5000", (ctx) => {
    console.log(`${getNow()} 【成功】任务 B (Key: ${ctx.key}) 按时触发。`);
}, "task_B");

seal.ext.registerTask(ext, "once", "2000", (ctx) => {
    console.log(`${getNow()} 2秒任务启动，尝试删除 task_A...`);

    const count = seal.ext.removeTask(ext, "once", "task_A");

    console.log(`${getNow()} 移除操作完成，实际移除数量: ${count}`);
});
