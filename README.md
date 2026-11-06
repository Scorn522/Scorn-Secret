# Secret 4.3 单目标开发分支

公开开发仓库：[Scorn522/Scorn-Secret](https://github.com/Scorn522/Scorn-Secret)。本地维护者 Scorn；上游作者署名及各组件许可证保留。

当前候选：[Secret-4.3-local-test-r15.jar](releases/Secret-4.3-local-test-r15.jar)（1,489,743 字节）。r15 已通过构建与离线检查，尚未完成实机验收；后续四件物品的加强方案仍处于审查阶段，未包含在本候选中。检查源码留在开发源集，不打入游戏 JAR。


基于 `Secret-4.3-local-test-r2`，固定开发目录为 `D:\桌面\Secret-4.3-dev`。版本 `4.3-local-test-r15`，保留原 Mod ID、Java/JNI 命名与资源。原始下载源码及独立 Scorn Secret 工程没有覆盖。

## 本批行为

- 范围动作合并同批目标登记与处决状态通知，避免逐目标重复发送整份状态。
- 服务器统一登记处决，客户端按同步目标摘除；移除处决后每 Tick 全世界重扫。网络协议升级，拒绝与 r2 客户端混用。
- 攻击记录使用维度、目标 UUID 与实体 ID，不再按实体类型或玩家名字永久封禁；右键范围动作仅选取当次现有对象，后续正常新召唤对象不进入该次处决范围。
- 世界实体表、tick active/passive、玩家列表与背包沿用原生容器，不安装同步代理。入场入口按当前维度已处决 UUID 拒绝回填；Owner 维护只核对自身身份槽位，异常时修复。保留原版 tick 双表交换、退出和换维度。
- 精确清理目标类静态实例引用和一层包装引用；支持黑日 BossRecord 的 uuid 与 SuperSteve SSSaveData 的 UUID NBT 条目。未知持久化结构不猜测、不整表清空。相关 SavedData 修改后标脏。
- 清理由实体字段关联的服务端 BossEvent 发送移除，并同步精确血条 UUID 到客户端；不按标题、类型或 Mod 批量清除。
- Owner 背包使用原生 NonNullList。武器记录在合法交互后更新，异常丢失仅到期检查或事件触发后恢复一份；不占用 selected、不覆盖已有物品。正常菜单、拾取、存档加载、创造物品包和使用动作保留 finally 作用域，没有修改挖掘包处理器。
- Owner 拒绝非有限坐标/速度、关键战斗属性非法归零和直接负面修改；原版装备/药水更新走合法作用域，自定义属性不以负数一概判恶意。不再每 Tick 清空全部药水效果。
- 普通第三方事件正常分派，删除原来的全局非核心事件压制。未增加整 Mod 停用、方法置空、工厂置空、线程挂起或全 JVM 监控。

## 构建

设置 JDK17 的 `JAVA_HOME`，Python 和 Zig 0.13.0 可分别用 `HIMITSU_PYTHON`、`HIMITSU_ZIG` 指定，然后执行 `./gradlew.bat build --console=plain`。
默认仅编译、离线检查和打包，不启动游戏、部署或上传。最终包为 `build/libs/Secret-4.3-local-test-r15.jar`，不要安装 intermediate JAR。原 r2 的本地开发配置和退出协调修复保留。

## 证据与边界

本批离线检查对象身份会话、LocalChannel、FakePlayer 分流、精确入场规则、原生 Tick 双表交换、武器恢复和生产方法接线。它不能替代真实 Forge/PCL 对战、联网同步、FPS 或保存退出验收。

按本轮选择，防回填依赖世界/实体管理器等入场钩子。直接绕过这些入口写容器或底层数组，不再由 GuardedContainers 当场拦截；Owner 已知身份槽位仍有维护。任意 Native 篡改不在新增覆盖内。只清理明确关联的记录，不把新 UUID 的实体猜成原目标，不承诺通用“断绝一切复活”。

上游 Secret 4.3 作者为 himitsu（原元数据声明 MIT）；本地修改由 Scorn 维护，原资源及第三方许可证保留。

## r4 启动时序修复

11:52 运行的两份线程快照中，Secret 的 RedefineClass 和 ArcaneVortex 构造器的批量重转换相隔 123 秒均未推进。r4 在构造阶段只发布原有防护配置和安装类加载钩子，将原有完整恢复流程交给 FMLCommonSetupEvent.enqueueWork，在所有 Mod 构造完成后执行。

没有删除或缩小原有类回放、回滚、Native 防护或目标范围。每次重定义增加开始/返回日志，用于下一轮定位具体未返回的类。本轮改的是 Java 初始化时序，Native 生产源码未变。

这针对已观察到的并发启动触发条件；尚未取得 Native 锁持有者证据，也未实机证明全部冲突消失。现有卡住的 JVM 不会因磁盘上的新 JAR 自动恢复，仍需之后重启验证。

## r5 启动资源加固

2026-11-05 提交的错误报告中，Secret r4 在 Native 初始化前报 `Missing native resource: /himitsu.d11`。安装包与构建产物 SHA-256 一致且包含正确 DLL。Pig2 2.8.3 的 `MyXformer2.tranNodes_dllString` 对匹配类的方法 LDC 字符串执行大小写不敏感的 `.dll` → `.d11` 替换，与现场一致。

- SecretNative 改为通过 `System.mapLibraryName("himitsu")` 动态解析原生库名，资源名、解包文件名来自同一个结果。移除易被此规则改写的 DLL 路径字面量，没有增加错误文件名兼容副本。
- 构建按实际打包的 Native 二进制生成摘要。运行时先验证资源 SHA-256，再写临时文件、读回校验并替换目标，失败时清理临时文件。摘要只证明包内一致性，不声称能抵挡攻击者同时替换代码、二进制和摘要。
- 保留 r4 初始化时序与原有防护，不修改 Pig2 或其他 Mod，不添加全局停用、反击或游戏热路径扫描。
- 新检查直接读取最终 JAR 的引导类并复现上述 DLL 字面量改写，验证资源解析、重复解包、丢失/损坏/异常摘要拒绝以及替换失败清理。检查不执行 Pig2 的类初始化和 Native 监控，也不加载 Secret DLL。

`build --offline --console=plain --no-daemon` 成功（21 项任务，18 项执行、3 项复用）。`checkNativeBootstrap`、`checkTargetGuards`、`checkLocalShutdown`、`checkNativeShutdown` 及最终包校验通过；Native 生产源码未改。无游戏部署、启动或 Git 提交推送。本次仅验证具体资源名改写入口，不能宣称与 Pig2 的其他转换/Native 监控全面兼容，仍需独立实机验证。

## r6 通用原生桥接抗转换（小范围修改）

新报告对应 r5，安装包哈希一致。05:47 的 Native 日志已完成 DLL 加载与早期守护，但内嵌桥接定义后 `RegisterNatives` 返回 -1，Java 随后等待十秒报错。外部转换器存在去除 native 标记并重写方法体的规则；先前日志清除了原始 JNI 异常，不能把最终 ClassNotFoundException 单独当作真正起因。

生产变更仅涉及 SecretNative、native_bridge.cpp 和 ClassDefense 的一个资格判断：

- 用 JDK 17 `Lookup.defineHiddenClass` 定义自身内嵌桥接，保留原有 invoke/ready 的签名、同步语义、调用计数、验证与退出门控。不按对方 Mod 名、版本或特定方法名选择应对路径。
- JNI 注册和监控准备成功后，直接发布真实 Class 引用；Java 不再按全局类名反复解析桥接。删除原有按签名查找/复用公开桥接与 JNI DefineClass 路径，内嵌 NativeBridge 字节码仍为唯一 ABI 来源。
- 隐藏类不参与重定义。原有 JVMTI 心跳继续运行，探测对象改为自身普通 SecretNative 类；未关闭全局监控或其他保护。
- 注册失败保留原始 JNI 异常并交接失败状态，避免已知失败继续等待后只显示模糊超时。

隔离检查使用测试专用小 DLL 和定向 Java agent，分别修改普通桥接的 native 标记、方法名，验证注册拒绝；随后使用生产 Java 定义/解析方法验证隐藏桥接真实 RegisterNatives、ready/invoke 往返、不可按名称发现、持有启动监视器时的并发发布，以及失败状态直达。没有运行对方 Mod 或 Secret 生产 DLL 的守护逻辑，不能替代真实 Forge 共存测试。

最终构建 `build-r6-bridge-final.log`：27 秒成功，24 项任务（20 项执行、4 项复用）；Java 与 Native 编译、桥接检查、r5 资源完整性检查、Owner 守卫及 Java/Native 退出检查通过。首次检查因普通测试类使用无名 defineClass 导致目标过滤未命中而失败，修正为显式类名后重新通过。未部署、未启动游戏、未提交推送。

该机制保护自有桥接的标准类转换边界，不承诺抵挡任意 Native 内存改写、JNI 函数表劫持或启动代码本身被完全替换。API 参考：https://docs.oracle.com/en/java/javase/17/docs/api/java.base/java/lang/invoke/MethodHandles.Lookup.html

## r7 通用启动恢复与自身真值护盾

本批完整源码直接保存在 `D:\桌面\Secret-4.3-dev`，旧源码备份在 `.work/r6-before-self-healing`。没有对任何对方 Mod 的名称、版本或特定类建立判断分支。

1. **两阶段引导**：新增 `ITransformationService` 服务和服务声明，先安装 Native 保护；`SecretMod` 保留兜底并单独申请游戏层桥接。服务层依赖不可见时明确记录降级到 Mod 入口，不宣称服务一定抢先所有未知服务。多加载器通过桥接申请标记区分，重复提取只复用经过摘要校验的同一 DLL。Java 等待使用最多 2400 次计数循环与 parkNanos，Native 等待亦有上限。
2. **三表恢复与严格隔离**：JavaVM/JVMTI 恢复基础上补齐当前 JNIEnv 表恢复，核对磁盘与已加载 JVM 的 PE 元信息。普通/检查版 JNI 表需唯一且至少三分之二函数槽匹配才采用，不按扫描顺序猜测。严格模式清空已验证 HotSpot 环境链中外部环境的标准、扩展回调，禁用全局与线程级事件，并守卫回调注册入口。取消借用其他 Agent 环境恢复自身的旧路径。
3. **原生桥接闭环**：先恢复 JNI 并隔离外部回调，再通过 JNI DefineClass 定义。检查非 Object、方法归属与 static/native 标志、RegisterNatives、ready 原生入口命中以及 invoke 的对象身份往返。普通定义失败后有一次原字节重定义尝试；错误 71 等不支持情形使用经过同样自检的隐藏类兜底。仅成功后发布真实 Class 引用，失败交接原始日志与状态。
4. **字节码真值**：打包时列出明文引导类，Native 从自身 JAR 读取、缓存并修复已加载类；107 个加密业务类在原生认证解密后登记不可覆盖的原始字节。类加载回调只查内存缓存，不在回调内读盘/解密。自身恢复后保留合法内部钩子；取消 Java 回调也不会关闭 Native 真值护盾。选定的 java.base/jdk.unsupported 核心类先取模块资源原字节，再在重转换回调中覆盖，避免将单纯 Retransform 误认为从镜像恢复。

没有按“非标准”批量移除 LaunchPluginHandler 中的 Forge/Mixin 或其他插件。对自身与指定核心类的改写通过真值覆盖处理；缺少行为判据时不擅自把其他 Mod 的合法转换判为恶意。注册后可用的新外部代理入口被限制，但本机任意 Native 内存写或持有旧原生函数指针的对抗仍不能获得绝对保证。

**严格模式的实际取舍**：`JVMTI禁用=true` 会同时停止合法 Java Agent 的回调、调试/探针等活动，不是“只识别恶意 Agent”。此次部署按用户要求启用，旧配置备份保留。`false` 是兼容选项，不具备严格外部隔离保证。HotSpot 环境链检查仍依赖受验证的 Windows x64 HotSpot 17 布局；未知布局或无法明确匹配的表会拒绝恢复，不承诺任意 JVM 通用。

### 本轮验证

- `build-r7-acceptance.log`：完整构建和检查成功，36 秒；Java/Native 均实际编译，25 项任务（18 项执行、7 项复用）。
- 既有资源摘要、桥接改写/重命名、Owner 守卫和 Java/Native 退出检查全部通过。
- 使用 PCL 同款 Microsoft Java 17，在独立 JVM 中加载本轮生产 DLL：服务/游戏双加载器交接、隔离测试 Agent、普通桥接原生自检通过；检查进程正常退出。
- 107 个认证业务类全部登记；实际改写自身服务类后恢复，合法内部钩子保留，注销 Java 回调后 Native 护盾仍有效；无关测试类仍能正常定义与更新。
- 日志确认选定的 7 个 JDK 核心类恢复返回 JVMTI 0。此前发现普通/检查版 JNI 表歧义，已修复后重新验证。
- 没有启动 Minecraft/Forge 世界，没有 FPS、攻防实机或保存存档验收，不把独立 JVM 结果冒充游戏通过。

JVMTI 限制参考：https://docs.oracle.com/en/java/javase/17/docs/specs/jvmti.html#RedefineClasses

## r7 线程跳板崩溃修复（2026-11-05）

实例两次发生 Windows 原生访问异常，转储为 java.exe.115740.dmp 与 java.exe.93900.dmp。两次故障均位于 Secret 自行分配的 JVM_SuspendThread 跳板 +0x19，返回栈含 himitsu.dll+0x1a341。Microsoft Java 17.0.15 的该导出在 +0x0a 处有一条 6 字节指令；旧实现固定复制 12 字节，将这条指令截断，随后拼接的跳转地址被当作原指令的操作数执行。该根因属于 Secret 自身，无需对外部 Mod 做特判。

将 JVM_StopThread、JVM_SuspendThread、JVM_GetAllThreads 全部迁移到工程已有 MinHook 的完整指令解码/重定位，删除固定 12 字节复制和手写 RAX 跳转。所有原入口先发布、后批量启用，失败回滚关闭入口。退出时关闭钩子但保留三个小型跳板直到进程结束，避免已经进入回调的线程使用被释放的内存；渲染层只撤销自己的钩子，不再卸载共享 MinHook 后端。

新增生产 DLL 检查覆盖受保护线程的挂起/停止拒绝及枚举隐藏、普通线程挂起/恢复/停止与枚举、退出时并发枚举和退出后的正常调用。上一轮独立启动没有调用这些 JVM 线程入口，未覆盖本次崩溃路径；不能以此前通过代替本轮验证。

`build-r7-thread-fix.log` 完整构建与全部离线检查成功（36 秒，25 项任务，16 项执行、9 项复用）。生产 DLL 在 PCL 同款 Java 的独立 JVM 中完成上述检查并以 0 退出；107 个业务类、真值恢复、桥接与 Owner 守卫检查继续通过。已替换实例中的同名 r7 JAR，原包与部署哈希保存在 `.work/deploy-r7-thread-fix-20261105`。配置未改，Minecraft 未启动，实机结果未验证；无 Git 提交或推送。

## r8 启动恢复收敛与实机结果（2026-11-05）

PID 95896 的两份线程快照相隔约 192 秒，Render thread 一直停在 ClassDefense.initialize → DumpClass，后台线程同时停在 Java 类转换回调；两者 CPU 均未推进。保留现场后按用户要求收敛既有实现：

- ClassDefense.initialize 仅确认 Native 桥已就绪并发布配置，删除全 JVM 扫描、逐类 DumpClass/RedefineClass 以及仅供该循环使用的判定和记录；不再向 COMMON_SETUP 主队列添加全量恢复任务。
- 删除周期性重转换心跳、探测类引用及对应旧探测/恢复入口。监控保留指针、环境链、阶段与能力检查及异常状态恢复，不主动提交重转换心跳。
- DumpClass 沿用现有线程局部作用域方式记录每次请求，支持嵌套采集；删除全局 dump_operation_lock/dump_lock，不跨 JNI 回调或 Safepoint 持有原生采集锁。
- r7 的 SourceShield、合法内部钩子、原生桥自检和线程跳板修复保留。没有新增保护框架，也没有扩大 Mod 拦截范围。

完整构建和独立生产 DLL 检查通过：55 秒，25 项任务（22 项执行、3 项复用）；新增嵌套 DumpClass 和无后台重转换检查通过，其余线程保护、真值与退出检查继续通过。

已备份 r7 并部署 `mods/Secret-4.3-local-test-r8.jar`，移除实例中的 r7。沿用原 PCL 脚本、参数和其他 Mod。实际启动存在进程接力：111936 以 0 退出后，子 Java 94836 继续运行；前者的退出码不能当作最终游戏的退出码。最终进程日志在 08:05:50 确认玩家加入世界，并记录三维度保存；用户反馈“没问题了”。主菜单/启动卡死问题本轮验证通过，游戏留给用户操作，没有强制退出。窗口工具初始化失败，因此画面结果依据用户反馈与运行日志，未宣称截图确认。FPS 与完整武器功能未测，无 Git 提交推送。

证据：`.work/hang-20261105-0742`、`build-r8-startup.log`、`.work/pcl-r8-menu-check/acceptance.json`。

## r9 Secret 武器左键入口修复（2026-11-05）

用户确认是拿 Secret 武器时右键可处决 Pig 目标、左键无效。源码对比发现左键使用 128 次普通 Level.getEntities 查询及 hurtEnemy 成功伤害后回调，而右键通过世界实际实体容器取目标；免伤、查询过滤或普通攻击链取消会让两者表现不同。本轮没有针对 Pig 的名称/类名做特判。

生产仅修改 CivilizationSurvivalItem 与 CivilizationSurvival：以 onLeftClickEntity 前置直接命中处决，移除冗余 hurtEnemy 入口；服务器挥击改用右键同一实体快照，再按原来的 128 个半径 0.5 方盒检测射线。直接读取目标包围盒字段，不反复调用世界查询。候选按对象身份去重，同一目标一次挥击只处置一次；仍调用原 killTarget，保留 Owner/SecretEntity 保护及精确实例标记，不停用整个 Mod，不封禁后续新实体。客户端不再重复做 128 次实体查询。

build-r9-left-click.log 构建与既有检查成功（48 秒，24 项任务，20 项执行、4 项复用）。新增几何检查覆盖前方、后方、侧方、最后一个采样盒、超距和相切边界。Native 生产代码未修改。已备份 r8 并部署 r9，其他 Mod 与配置未改，未启动游戏或提交推送；实际左键交互尚待实机确认，不能以构建成功代替对 Pig 的操作验收。

## r10 左键客户端放行与挥击判定修正（2026-11-05）

r9 的 onLeftClickEntity 在客户端也返回 true；r10 改为客户端返回 false，保持客户端攻击流程，服务端调用原 killTarget 后返回 true。没有新增网络包或改动服务端目标权限、Owner/SecretEntity 排除与单实例处置。

挥击使用 128 格连续线段、3.5 格粗筛扩展，优先读取目标包围盒（空时使用原字段），在原步进样本之外增加扩展包围盒连续求交；射线未命中时，按与玩家距离不超过 6 格且正面点积大于 0.3 判断近战兜底。不是 3.5 格全区域处决；远处目标仍需命中射线或步进样本。保留原实体快照来源，未增加 Pig 特判或逐 Tick 扫描。

build-r10-left-click.log：完整构建成功（43 秒，24 项任务：20 项执行、4 项复用），Java 编译、Native 构建任务、桥接/引导/目标守卫与 Java/Native 退出检查通过；新增连续射线采样间隙、128 格端点与眼点包含检查通过。Native 生产源码不变，未另跑生产 DLL 启动检查。已校验备份 r9 后部署 r10，安装包 SHA-256 与构建产物一致，其他 Mod 文件名/大小/修改时间未变。未启动游戏或提交推送，实际发包及对 Pig 左键处决未实机验收。

## r11 挥击入口脱离可被跳过的物品回调（2026-11-05）

用户实测 r10 仍无法直接左键处决 Pig2，但攻击旁边其他实体时可以连带处决。定点检查实例中的 Pig2 2.8.3 字节码：MxPlayer.attack 取消对其目标的普通攻击；MxItemStack.onEntitySwing 调用 permitItemSwing，在正面瞄准对应目标时直接返回，根本不调用 Item.onEntitySwing。这解释了为什么加大射线与修正物品回调返回值仍不足以解决本次触发问题。

另外，已核对 Forge 的 MultiPlayerGameMode.attack：它先发送原版攻击包、再调用客户端 Player.attack。因此 r10 客户端返回 false 的修改仍保留，但此前“返回 true 一定吞掉交互包”的解释不适用于这条已核对调用链。

本批仅修改两个生产 Java 文件：删除武器旧 onEntitySwing 回调，使用已有 AsmHook 的 HEAD 模式在 LivingEntity.swing(InteractionHand, boolean) 进入时调用原有挥击逻辑。只有服务端玩家且本次挥手对应手确实持有 Secret 武器时执行；原版动画、其他物品回调及其他 Mod 代码继续运行。使用原版 ServerboundSwingPacket，不增加新协议、不修改对方 Mod，也不把范围改成全场攻击；r10 的几何判定及单实例处置保持不变。普通挥手仅做固定类型/侧别/持物检查，不爬栈，不新增逐 Tick 扫描。

新增离线检查在实际 LivingEntity 方法结构中模拟“完全跳过物品回调而返回”，确认开发名与运行名两种方法均在返回前触发且只触发一次；同时检查已删除旧物品回调。build-r11-swing-entry.log 构建成功（46 秒，24 项任务：20 项执行、4 项复用），新增入口织入检查及既有桥接、引导、目标守卫、Java/Native 退出检查通过。Native 生产源码不变，构建任务正常执行；未额外运行生产 DLL 启动检查。已校验备份 r10 后替换为 r11，安装包与产物 SHA-256 一致，其他 Mod 文件名/大小/修改时间未变。未启动游戏或提交推送；本轮只有源码、织入与离线检查证据，直接左键 Pig2 尚待用户实机验收。

## r12 按两文件约束收敛挥击入口（2026-11-05）

依照用户追加的禁止扩张要求，撤回 r11 的 LivingEntity HEAD 钩子，CivilizationSurvivalHooks 恢复至 r10 原件。相对 r10 的生产改动仅在 CivilizationSurvivalItem（删除失效的物品挥击回调）与 CivilizationSurvival（复用已有服务端 LevelTick END 维护入口）。没有增加类、库、协议或 Native 改动；保留直接命中回调、r10 几何范围、Owner 保护与单实例处置。

原版收到挥手包后仍会更新 swinging/swingTime，即使 ItemStack 跳过武器回调。本批仅在主手持有本武器、主手正在开始挥击时进入现有 swing。用 tickCount-swingTime 识别同一次挥击，避免阶段 -1 与阶段 0 重复扫实体；弱键表不持有退出玩家，且只在已有服务端事件线程访问。平时仅做几个字段/持物判断，只有真正新挥击才执行原有实体快照；不新增全场逐 Tick 扫描。依赖原版挥手包和动画状态仍存在，若其他代码完全吞掉两者则不声称此入口能凭空恢复输入。

必要检查新增收到包/首动画 Tick 去重、首次仅观察到阶段 0、中途动画不攻击、下一次挥击恢复。现有 CivilizationSurvival 原已超过 200 行，本次不为压行数拆类或重写无关功能；仅就地加入必要的状态识别。build-r12-compact-swing.log：完整构建成功（42 秒，24 项任务：20 项执行、4 项复用），新增挥击阶段去重检查及既有桥接、引导、目标守卫与退出检查通过。Java 和 Native 构建任务执行，Native 生产源码未改。最终 JAR 1545249 字节，低于 2,000,000 字节；已备份 r11 后自动部署 r12，安装摘要一致。未启动游戏或提交推送，直接左键实机效果、秒进与零卡顿均未验证。

## r13 通用攻击与挥手 HEAD 入口（2026-11-05）

用户反馈 r12 连此前旁侧挥击处置也失效，r12 不视为功能通过。该轮日志记录三维度保存、Minecraft Stopping 与 Native 运行时关闭，未见新崩溃；源码确认 r12 删除了已有物品入口并依赖 Tick 轮询，同时加载钩子注册晚于 Player/LivingEntity 的解析，Native 日志未见这两个目标的应用记录。仅添加方法而不补齐已加载类接线不足以闭环。

按用户新方案：CivilizationSurvivalHooks 给 Player.attack(Entity) 与 LivingEntity.swing(InteractionHand, boolean) 添加 HEAD。只有服务端主手持有 Secret 武器才执行；直接目标继续交给 killTarget 的 Owner/SecretEntity 排除和单实例处置，挥手继续使用 r10 几何规则。不匹配 Pig2 或任何对方 Mod 的类名、ID、版本；原方法及第三方逻辑保留。完全删除 r12 的挥击轮询、弱键状态表与阶段推算，不并行保留旧方案。

在现有 SecretRuntime 初始化中排队一次双目标安装，使用现有 Native RetransformClass，仅对 Player 和 LivingEntity 各处理一次，并使用现有 HookRegistry.audit 确认两条方法匹配。失败明确报错，不静默宣称已安装；不恢复全 JVM 枚举/等待循环、不加入周期重转换。该安装安排在并行 Mod 构造完成后的 COMMON_SETUP 队列，与已删除的全量恢复循环不同，但两次定向转换的实际启动耗时仍待实机确认。

本轮生产改动为 CivilizationSurvival（退掉轮询）、CivilizationSurvivalHooks（两个入口及一次安装）、SecretRuntime（两行生命周期接线）；未增加类、库、网络协议或 Native 源码。离线检查模拟目标方法直接返回，核对开发名/运行名下回调先于返回且重复织入仍只执行一次。build-r13-direct-entries.log 构建与相关检查成功（48 秒，24 项任务：20 项执行、4 项复用）。随后按用户要求，r13 暂不部署，实例切回原版 r11 供对比测试；r13 源码与候选仍保留。本轮未启动游戏，不以模型检查冒充 Pig2 实机通过。


用户实测 r11 仍无效后要求安装 r13。部署前实例已关闭、mods 中已无 Secret JAR；现已安装 Secret-4.3-local-test-r13.jar（1547973 字节，SHA-256：4CD9CAB57ADDC5CBB8B2DE7D33E3052377A827E4C6D5299B19F1E24034E0CE1A），与已通过检查的构建产物一致。其他 Mod 未改，旧版本历史备份保留。本轮未启动游戏或提交推送，r13 实机结果待验证。

## r14 会话身份、精确拒签与部件处置（2026-11-05）

基线为用户已确认左键恢复正常的 r13。CivilizationSurvivalHooks.java 与 r13 备份逐字节一致，包括 weaponAttack / weaponSwing 及其安装；没有修改这两个已经生效的挂钩。所有生产修改在原有类内，未增加生产类、外部库、协议或 Native 功能。

- Owner 查询只读已绑定玩家/会话，不再用名字或裸 UUID 提供豁免。绑定前核对真实玩家列表、连接与玩家对象，显式排除 FakePlayer；本地 LocalChannel 与网络通道同等接受。客户端只绑定本次连接中实际存在的玩家对象，保留登录、退出和换维度的既有生命周期。
- 左键、右键与客户端目标同步共用真实玩家分流：只有认证会话玩家走 Tick 表特殊移出，FakePlayer 与未认证替身走完整底层移除。右键不再按相同 UUID 跳过任意冒牌对象。
- ServerLevel.addEntity、PersistentEntitySectionManager.addEntity 与 addEntityWithoutEvent 的入口按现有维度/处决 UUID 拒绝回填，容器回填规则同步使用同一判定。不同 UUID 的正常新实体不被封禁；Owner 的真实登录、合法换维度不因同 UUID 假人的处决记录被误挡。
- 一次攻击先收集 PartEntity 的母体和对应 parts，按对象身份去重后批量标记/清理，能终止循环父指针。Owner/Secret 根直接排除，不扩散到普通乘客和坐骑，不增加全世界周期扫描。
- 去掉清理时的目标 stopSeenByPlayer 调用，直接清空相应追踪观看集合、移除容器关系并发送原版 ClientboundRemoveEntitiesPacket。没有新增网络消息类型。
- 既有 OwnerSafety.Binding 保存一份武器数据副本；仅异常彻底丢失时向空槽恢复一份，不改 selected、不覆盖物品。光标中拿着武器不算丢失；合法容器/物品操作结束后更新记录，主动转移不会再生。满背包时等待空槽，不挤掉其他物品。
- 接线复用 COMMON_SETUP 队列，在 r13 双入口安装后，对事件分派、实体入场及既有背包/生命周期的八个明确类各定向安装一次，不枚举全 JVM、不使用后台重转换心跳。

内部检查放在原 check 源集，不进入游戏 JAR。新增真实 LocalChannel 会话夹具、同 UUID 冒充、Owner 换维度例外、维度/UUID 精确拒签、部件循环/去重与骑乘排除，以及武器 NBT 恢复、光标/合法容器转移、满包不覆盖和不重复恢复检查。离线夹具不启动 Forge、服务器或世界，不能代替游戏内验收。

build-r14-final.log 完整构建成功（36 秒，24 项任务：11 项执行、13 项复用）。Java 实际编译，Native 生产源码未改、最终构建复用已有 Native 产物；桥接、引导、目标守卫与 Java/Native 退出检查通过。新增生产类为 0，仍为 111 个；r13 攻击挂钩文件以及 TargetLedger 源码/字节码保持一致。最终包 1558981 字节（约 1.56 MB，比 r13 增加 11008 字节），最终包及加密前输入均无测试类、检查工具、测试 DLL、脚本或日志。已备份 r13 后部署 r14，安装 SHA-256 为 45D6A56A9B3FD13A5103F5346498660F5528C64F7AAE0DC16B971AE838A74F1A，与候选一致；其他 Mod 未改。未启动游戏，不提交推送；普通生存操作、对战效果及性能仍需实机验收。

## r15 身份热读与原生容器收敛（2026-11-05）

定点对照下载目录中的原作者 AuthoritativeEntityTopology / CivilizationSurvival，以及 `.work/r13-before-r14` 中的 OwnerSafety 与 CivilizationSurvivalHooks。原参考目录和 r13 快照未改动；未新增源码、脚本、库、协议或生产类。

- 删除 GuardedContainers 及 OwnerSafety.Slots，EntityTickList、visibleEntityStorage、knownUuids、players、Inventory 回归原生容器。删除自行复制全部 Tick 实体的 forEach/contains 覆盖及无读取方的 Tick 注册表，保留原版 active/passive 交换和实际写入口的轻量目标判定。
- OwnerSafety.owns / CivilizationSurvival.isOwner 只按 Player 对象身份查只读快照和状态位，不查 Netty、PlayerInfo、ThreadLocal，也不加锁。会话校验移到登记/生命周期；连接关闭即时使已有记录失效，换维度与重生重新绑定，客户端玩家名单/角色同步变化时刷新。
- AuthoritativeEntityTopology 的锚点表改为只读身份快照；自身节区成员与玩家列表使用缓存槽位核对，位置失配才搜索对应列表。跟踪表正常路径只按实体 ID 核对对象，不再整表计数。
- 已登记 Owner 不再每 Tick 重绑或全背包扫描；武器恢复每 20 Tick 到期检查，合法交互更新记录，丢弃事件可提前触发。保持武器 NBT、光标拿取、合法转移、满包等待及不覆盖物品；健康/效果同步先比较原始数据项。
- 保留 FakePlayer 排除、真实会话玩家分流、同维度被处决 UUID 拒签、多部件身份去重及 Owner/Secret 排除。CivilizationSurvivalHooks 与实测 r13 的 SHA-256 一致，weaponAttack / weaponSwing 未改。没有新增整 Mod 停用或 EntityType 工厂修改。

本轮只构建和离线检查，不部署、不启动游戏、不提交推送。容器直接写绕过入场钩子的缺口是此次移除代理的明确边界；没有用离线检查宣称游戏性能或攻防实机通过。

最终完整构建成功：50 秒，24 项任务（11 项执行、13 项复用）。Java 实际编译；Native 生产源码未改，最终构建复用已有 Native 产物与已通过的退出检查。桥接、引导、目标/生命周期检查本轮通过。生产 class 从 111 个减为 95 个，新增为 0；最终包及加密前输入没有测试类、测试 DLL、脚本或日志。候选 1489743 字节（约 1.49 MB），SHA-256：`972FB4A99A82DDC128B19871B38E1A9CE423F700081E50B4274BD1A4FE89A80D`。实例仍保留 r14，本批未部署。
