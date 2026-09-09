globalThis.pluginCompatFixture = {
  host() {
    const message = seal.newMessage();
    message.message = "hello";
    const extension = seal.ext.new("fixture-extension", "test", "1");
    return {
      functionTypes: [
        typeof seal.vars.intGet,
        typeof seal.vars.strSet,
        typeof seal.ban.addBan,
        typeof seal.ban.remove,
        typeof seal.ban.getList,
        typeof seal.ext.new,
        typeof seal.replyToSender,
        typeof seal.newMessage,
      ],
      extensionMethods: [
        typeof extension.storageGet,
        typeof extension.storageSet,
        typeof extension.storageList,
      ],
      roundTrip: atob(btoa("Scardice")),
      forward: seal.newForwardNode("1001", "骰主", "内容").senderId,
      message: message.message,
      versionType: typeof seal.getVersion().version,
    };
  },

  context(ctx, msg) {
    return {
      groupId: ctx.group.groupId,
      message: msg.message,
      sender: msg.sender.userId,
      private: ctx.isPrivate,
      privilege: ctx.privilegeLevel,
      delegate: ctx.delegateText,
    };
  },

  mutateContext(ctx) {
    ctx.isPrivate = true;
    ctx.commandHideFlag = "hidden";
    ctx.delegateText = "changed";
  },

  errors() {
    const ext = seal.ext.new("unregistered-fixture", "test", "1");
    try {
      seal.ext.registerStringConfig(ext, "missing", "default", "description", "");
    } catch (err) {
      return String(err);
    }
    return "no error";
  },

  callbacks(ext) {
    ext.onMessagePreprocess = function () { globalThis.pluginCompatOrder.push("preprocess"); };
    ext.onMessageReceived = function () { globalThis.pluginCompatOrder.push("received"); };
    ext.onCommandReceived = function () { globalThis.pluginCompatOrder.push("command"); };
    ext.onMessageSend = function () { globalThis.pluginCompatOrder.push("send"); };
  },
  durableSmoke(probe) {
    const plan = {
      transient: "$t",
      owners: ["$m", "$g"],
      attrs: "player",
      ban: ["add", "remove"],
      config: "extension",
      storage: "opaque",
      callbacks: ["preprocess", "command", "reply", "send"],
      lifecycle: ["group", "member"],
    };
    if (!probe) {
      return plan;
    }
    const transientBefore = probe.transientGet();
    probe.transientSet("changed");
    const storageBefore = probe.storageGet();
    probe.storageSet("opaque-after");
    return {
      transient: [transientBefore, probe.transientGet()],
      owners: [probe.ownerM(), probe.ownerG()],
      ban: [probe.banAdd(), probe.banRemove()],
      config: probe.config(),
      storage: [storageBefore, probe.storageGet()],
      callbacks: plan.callbacks,
    };
  },
};
