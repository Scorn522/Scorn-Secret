# Secret 4.3 单目标开发分支

公开开发仓库：[Scorn522/Scorn-Secret](https://github.com/Scorn522/Scorn-Secret)。本地维护者 Scorn；上游作者署名及各组件许可证保留。

当前本地候选：[Secret-4.3-local-test-r23.jar](build/libs/Secret-4.3-local-test-r23.jar)（1,585,040 字节，89 个业务类）。r23 完成第 4 部分首批精准清理：实例引用、可证明任务、同源持久化记录及部分完成状态。完整构建、Java 回归、Native 退出与两套 Java 独立启动通过；未知捕获和不可读任务保留。未部署、未启动游戏、未提交推送；最近已同步成品仍为 [r20](releases/Secret-4.3-local-test-r20.jar)。


基于 `Secret-4.3-local-test-r2`，固定开发目录为 `D:\桌面\Secret-4.3-dev`。版本 `4.3-local-test-r23`，保留原 Mod ID、Java/JNI 命名与资源。原始下载源码及独立 Scorn Secret 工程没有覆盖。

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
默认仅编译、离线检查和打包，不启动游戏、部署或上传。最终包为 `build/libs/Secret-4.3-local-test-r23.jar`，不要安装 intermediate JAR。原 r2 的本地开发配置和退出协调修复保留。

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


## r16 Java 处决与保护闭环（2026-11-06）

基线为 `80e508c` 的 r15；r13 `CivilizationSurvivalHooks` 保持逐字节一致，weaponAttack / weaponSwing 未改。本批仅修改既有 Java、接线资源、版本及既有检查文件，Native 生产源码未改，没有新增生产文件或生产类。

- **死亡继承**：Clone 先核对真实连接、服务器和 UUID，只迁移同会话新对象；在监听器和玩家表完成交接后再执行、发布最终身份。不把同 UUID 的任意对象直接当作继承者。死亡维护按登记时建立的分世界玩家数组读取，删除全服玩家扫描、每 Tick 锁表复制及无变化的整表清理；正常连接关闭释放会话状态。
- **写入口保护**：在既有 OwnerSafetyHooks 中接入 Entity.remove/setRemoved/kill 与 LivingEntity.setHealth/heal、Entity.revive。处决优先于 Owner，正常重生、换维度和退服沿用生命周期作用域。补齐 Entity、AttributeInstance、AttributeMap 的一次定向重转换和必检审计；LivingEntity 仍通过已有武器安装批次接线。没有拦截 disconnect、挖掘包或普通药水使用。
- **秘密实体拓扑**：入界完成后才登记，每个实际 Level 保留首个权威 Secret；按玩家/Secret 各自合法在场条件修复索引、Tick 与节区。节区丢失时重建并修正原版移动回调的节区引用，保留未知自定义回调。世界卸载先关闭维护并移除锚点；维度注册表和客户端代理分别解绑，不向已卸载世界重新填实体。
- **定向抽检与清理重试**：账本变更时预建分维度 Token/ID 数组，Tick 尾只核对已处决目标的 ID、UUID 和活动 Tick 槽位；数值 ID 被无关实体复用时不误删。没有恢复同步代理或全世界周期扫描。明确清理失败保留弱引用，自动重试最多三次、间隔至少 20 个服务端 Tick、每世界每 Tick 最多一个到期目标；重复拒签不重置额度，新一次明确命中可重开。未知持久化结构仍不猜测、不中断其他目标处置。
- **常态开销**：Owner 查询继续只读身份快照；AttributeMap 未命中 Owner 立即返回，命中才登记迟到属性。实体锚点维护数组也只在登记/释放时重建。新增正常抽检不分配临时数组、不爬栈、不加热读锁；异常修复仍可分配和复制相关容器，未测量实际 FPS。

完整 `gradlew.bat build --offline --console=plain --no-daemon` 成功：46 秒，24 项任务（14 项执行、10 项复用）。Java 本轮实际编译；最终构建复用已有生产 Native DLL。桥接注册、引导包完整性、Java 退出、Native 退出及目标守卫检查本轮执行通过；`test` 无源，实际回归由 `checkTargetGuards` 等现有检查任务运行。没有另跑生产 DLL 的 `checkNativeStartup`，未宣称 Native 强化或 Forge 实机验收完成。

新增离线检查覆盖 Clone 未就绪/就绪交接、同 UUID 异会话隔离、迟到属性索引与合法属性作用域、健康/移除守卫、原版 Tick 双表交换、ID 复用与 UUID 残留、三次重试上限及再次命中、节区回调重接、跨维度首实例及卸载屏障。首次离线检查因普通 JVM 缺少 Forge 事件类转换而不能创建网络监听表；已只在既有检查夹具中准备对应事件表，未修改生产网络实现。

最终包 1,514,597 字节，SHA-256：`08304FC70F570602BF3B44A5DC1878CC3B6450CA3C41A92C9BC98E835087C3EF`。生产 class 仍为 95 个；最终包及加密前输入均无检查类、测试 DLL、验证脚本或日志。r13 挂钩 SHA-256：`05F0CA04266AA07F7B38487908EE880F057CDB586D40531BF9049D3DC843974F`。起止 HEAD 均为 `80e508c`，既有未跟踪 CFR 文件保留；未部署、未启动游戏、未提交推送。


## r16-fix1 引导服务与 Forge Mod 登记修复（2026-11-06）

用户报告 r15/r16 均不在 Mod 列表中。核对 03:44 的实际 `debug.log`：正确实例发现 r16 的 `secret-bootstrap` 服务，但 Forge 游戏 Mod 扫描只登记 minecraft、forge、smartlook，没有 secret。对当前 Forge 47.4.23 的 `ModsFolderLocator.scanCandidates` / `ModDirTransformerDiscoverer.allExcluded` 定点检查确认：引导服务 JAR 被默认 Mod 文件扫描器排除。原 EarlyBootstrapService 只有服务入口，没有把自身重新登记为游戏 Mod。r13/r14 包也含同一服务声明；缺少那些可用场次的完整发现日志，不能据此断言此前由哪个外部组件或重启路径完成加载。

- 既有 EarlyBootstrapService 同时承担 Forge IModLocator，仅返回自己的真实 JAR 路径；新增一个 SPI 资源声明，不扫描其他 Mod，不修改 Forge 排除表。
- 同一 JAR 在服务/游戏两层直接使用自动模块会出现包导出或同名读取冲突。构建用已有 Forge ASM 依赖生成 541 字节 `module-info.class`：服务模块名为 `secret.bootstrap`，不导出业务包；Forge 游戏模块仍为 `secret`。保留单 JAR、双阶段 Native 引导，针对 PCL 的 LWJGL 类路径在启动时接上模块读取关系。
- 加密工具将模块描述作为明文装载元数据保留，不混入加密业务类或 Native 真值类列表。没有新增生产 Java 类型，业务 class 仍为 95 个；加密前 JAR 另外多一个 JVM 模块描述，合计 96 个 `.class` 条目。r13 攻击/挥击文件未变，Native 生产源码未变。
- 在现有 NativeBootstrapCheck 中增加真实 Forge Mod 文件解析、自身路径与 ID 核对，以及服务/游戏配置解析和独立类身份检查。父模块依赖仅建描述夹具，未模拟启动整个 Forge；独立生产 DLL 检查仍验证双加载器、90 个认证业务类、真值恢复、线程保护及退出。

`build checkNativeStartup --offline --console=plain --no-daemon` 成功，40 秒，26 项任务（14 项执行、12 项复用）。Java 在前序本轮编译完成，最终构建复用；生产 Native DLL 复用。MOD_DISCOVERY、既有桥接/引导/目标检查、Java/Native 退出与生产 DLL 独立启动均通过，检查进程退出码 0。没有启动 Minecraft，也未验证新包的实机 Mod 列表、物品或 FPS。

候选及安装包均为 1,516,449 字节，SHA-256：`57B2ADAEB1727CD8CA1F168E693BC5105DBE916A4B7666A20AC09F4276B7D598`。已备份 r16 到 `.work/deploy-r16-fix1-20261106-041305`，部署 r16-fix1 并移出实例 r16；其他 Mod 文件名、大小、修改时间未变。测试类、测试 DLL、脚本和日志未进入游戏包；未提交推送。


## r17 Native 线程保护与安全退出（2026-11-06）

工作基线为已确认加载正常的 r16-fix1 未提交工作区，起止 HEAD 均为 `80e508c`。保留此前 Java 闭环、Forge 自登记和服务模块隔离，r13 weaponAttack / weaponSwing 源文件逐字节不变。原有未跟踪 CFR 文件保留。本批不部署、不启动 Minecraft、不提交推送。

- **精确线程归属**：启动前 ProtectThread 只登记 Java GlobalRef；通过可信 JVMTI GetCurrentThread 与 IsSameObject 确认是当前执行线程后才复制 OS 句柄。维护线程在入口补登记；JVMTI/模块守护线程先挂起创建、登记句柄，再恢复运行。不会把初始化主线程误绑到待启动线程。
- **引用寿命收敛**：RuntimeState 发布不可变引用快照，读者用在途计数固定寿命。保护撤销、类转换与渲染回调替换统一延迟释放旧引用；JNI 调用及 DeleteGlobalRef 均在锁外。删除旧的共享可变保护向量和持锁 JNI 读写路径。回调回滚核对该槽位版本，保留并发的其他状态更新。
- **Win32 边界**：从 kernelbase 动态解析 CompareObjectHandles，以底层线程对象身份核对低权限复制句柄；Kernel32/KernelBase 入口按实际地址去重，使用现有 MinHook。拒绝 SuspendThread 返回 DWORD(-1)，拒绝 TerminateThread 返回 FALSE，均设置 ERROR_ACCESS_DENIED。普通线程保持原操作语义；MinHook 私有维护作用域及确认属于 JVM 映像的必要挂起调用放行。不以线程名字或裸 TID 作身份判据。
- **附加与分离**：初始化及恢复路径一起缓存 GetEnv、AttachCurrentThreadAsDaemon、DetachCurrentThread；工作线程从同一指针组取得环境，仅在自身执行了附加时配对分离。删除监控线程普通附加后无分离的旧路径，未新增重转换心跳。
- **退出**：自行管理的排空等待共用五秒截止时间，停止函数声明、调用和独立检查桩同步更新。正常退出后才关闭句柄和释放引用；调用或读者超时保留资源并返回未完成，重复关闭不会假报成功。Java 层记录不完整退出原因。MinHook 入口禁用后保留跳板和原函数指针；同一链路的 DirectX 退出从无限等待改为剩余期限，绘制期间有在途保护。
- **静态开销边界**：快照只在登记/撤销/回调变化时复制，正常读取不复制集合、不持引用锁；OS 身份查询只发生在被拦截线程操作上。渲染退出保护增加固定的 Native 在途计数，不新增逐帧查栈、鉴权或 JNI 通信。未进行 FPS/JFR 对比，不宣称实测提速。函数体恢复扩展及直接系统调用绕过不属于本批。

本轮完整构建及离线检查通过。首次完整构建 Java、Native 实际编译，54 秒；补齐引用单独超时检查后再次通过。最终 `build checkNativeStartup --offline --console=plain --no-daemon`：27 秒、26 项任务（15 项执行、11 项复用），Native 实际编译；Java 与未变化的独立退出模型复用本轮已通过产物。

`checkNativeShutdown` 本轮实际在三个独立进程中运行：正常排空、调用超时、引用读者单独超时，全部退出码 0。覆盖锁外 JNI、旧引用固定、同一截止时间、超时不释放、晚到调用拒绝、重复关闭未完成状态。最后构建因相关输入未变化显示 UP-TO-DATE，未冒充重新执行。

最终生产 DLL 的 `checkNativeStartup` 实际执行通过：预登记不保护调用方主线程、线程入口自登记、无查询权限句柄、Kernel32/KernelBase 拒绝值、普通线程挂起/恢复/终止、并发保护撤销/枚举、并发回调替换与采集、退出期间枚举均通过。日志确认 JavaVM/JVMTI/JNI 三表恢复，JNI 234 槽 ready=true；90 个认证业务类、桥接自检、Native 正常关闭及检查进程 ExitCode=0。既有 Forge 登记、Java 生命周期与 r16 目标回归继续通过；`test` 无源，实际回归由既有 check 任务执行。

最终 JAR **1,526,218 字节**，业务类仍为 **95 个**，另有现有 JVM 模块描述（536 字节）；最终包及加密前输入无测试类、测试 DLL、验证脚本或日志。JAR SHA-256：`D3E00547788927FEC78B2C9E11ACC6635A53F779AE42B3E33535C5A173F6A497`；生产 DLL SHA-256：`2CDFF5D157FE20EE228E92E554A070AD03244CE990E7AA496EA5827DEDA3CC68`。安装目录 r16-fix1 的摘要未变。实机启动、四件物品对战、保存退出和 FPS 尚未针对 r17 验收。


## r17-fix1 自身 JVMTI 恢复循环修复（2026-11-06）

起止 HEAD 均为 `80e508c`，保留此前全部未提交修改。仅修改现有 Secret Native 守护、既有检查文件、版本和本文；未修改秘法或其他 Mod。r13 `weaponAttack` / `weaponSwing` 源文件摘要保持不变。

- 环境成员判定在命中自身有效节点时立即返回，不因后续外部尾链超过 256 个节点或不可读而否定已找到的自身环境。明确区分“确定不在链内”和“无法完整判断”；未知状态明确报告，不盲目创建新环境。缓存位置异常时定点重新定位，失败定位限频。
- 合并两条恢复重试分支；非等待式单次恢复准入，失败候选保持私有并复用。校验通过才发布新环境；失败保留原环境，重试间隔由 1 秒递增到最多 30 秒。停止后拒绝继续创建环境，不恢复重转换心跳。
- 自有分发表恢复期间暂挂 ModuleGuard 的同表恢复，锁内仅更新 Native 标志，JNI/JVMTI 调用仍在锁外。表修复行为及累计次数保留，重复细节日志合并为每 10 秒最多一组，不因节流日志跳过实际修复。

`build checkNativeStartup --offline --console=plain --no-daemon` 本轮成功：64 秒，26 项任务（21 执行、5 复用）。生产 Native 实际编译，Java 生产源码未改且复用；检查 Java 与检查 DLL 实际编译。`checkNativeShutdown` 正常、调用超时、引用读者超时三场景全部实际执行通过。生产 DLL 的独立 JVM 检查增加 320 个真实 JVMTI 环境，确认自身回调仍可用、没有环境重建；既有线程保护、回调发布、Forge 登记及 r16 Java 回归通过。`test` 无源，回归来自既有 check 任务。

另用 PCL 的 `java-runtime-gamma-snapshot/bin/java.exe` 执行同一 `checkNativeStartup`（`-PsmokeJava`），25 秒、20 项任务（6 执行、14 复用），同样通过并以退出码 0 结束。没有启动 Forge/PCL 世界；与秘法共存及 FPS 改善尚未对新候选进行实机验收，不以离线结果代替。

最终包 1,526,055 字节，95 个业务类及现有模块描述；无测试类、测试 DLL、脚本或日志。SHA-256：`ED887CC74D64C200541EE1FAA4EFD776961C446D1D4B7B0BF5E9DBEE3271C65A`。已安装 r17 的 SHA-256 仍为 `D3E00547788927FEC78B2C9E11ACC6635A53F779AE42B3E33535C5A173F6A497`。未部署、未提交推送。


## r18 第三部分首批：基线、定向补偿与版本绑定（2026-11-06）

起止 HEAD 均为 `80e508c`；保留前序所有未提交修改。仅在既有文件内实现，没有新增生产 Java 文件或内部类，r13 攻击/挥击入口逐字节不变。死亡物品模型沿用原版缺省状态，不作为待修缺陷。

- **自修复基线**：`ClassDefense` 不再保存可变 Java 字节数组映射或在 Native 已认证输入之后二次覆盖它。`BootstrapPayload → SecretRuntime → ClassDefense` 全链迁移到 Native SourceShield；定义与最后使用方完成后只释放临时 Map 引用，不清零仍可能被使用的类字节。Native 源镜像初始化的短锁仅核对/发布归档状态，Java ZIP 读取、JNI 和 JVMTI 恢复全部在锁外；同源并发存储沿用既有不可变一致性核对。
- **Owner 状态直写补偿**：在既有 `OwnerSafety.Binding` 中记录有限坐标/速度的标量快照，避免与可被覆写的 Vec3 共用引用。只有已绑定 Owner 的维护入口运行补偿；遇到 NaN、Infinity 或空位置引用才恢复，维护位置、包围盒与方块索引。正常有效移动保留原对象，零分配、无爬栈、无 JNI；不限制合法有限坐标，不扫描其他实体。重生/换维度新绑定不继承旧维度坐标。
- **包与 Native 版本绑定**：现有打包器和生产解密器同步迁移到 HSP3，采用 HKDF-SHA256 的 extract/expand，将用途与包版本纳入派生上下文，继续以 AES-GCM 验证完整性。Gradle 将同一版本传入 Java 打包器、Native 编译及 Manifest；Forge 元数据使用 `${file.jarVersion}` 并通过实际解析断言核对。旧格式不回退，整包使用配套 DLL；临时派生密钥缓冲使用后清除。无新增依赖、网络协议或游戏内检查入口。[HKDF 规范](https://www.rfc-editor.org/rfc/rfc5869)

首次完整批次实际编译 Java 与 Native，Java/Forge 登记、目标守卫、Native 退出三场景和包绑定检查通过，但独立 JVM 在原有线程压力夹具中两次触发 45 秒超时。停点为普通 OS 线程强制终止之后的并发登记；既有夹具没有等待目标进入工作函数，存在在线程 loader/TLS 初始化阶段终止它的竞态。仅为测试线程添加就绪事件后，同一生产保护、原断言和 45 秒期限下检查通过（29 秒），未放宽生产防护。测试诊断及 DLL 均不入游戏包。

最终 `build checkNativeStartup -PsmokeJava=<PCL同款Java> --offline --console=plain --no-daemon` 成功：47 秒，26 项任务（13 执行、13 复用）。Java 本次重编，Native 复用本批已编译 DLL；`checkNativeShutdown` 在本批首次构建实际跑过正常、调用超时、引用读者超时三进程，最终因输入未变复用。`checkNativeStartup` 最终实际执行，生产 DLL 验证正确包可解密、错版本/错用途/改标签被拒绝；自身基线修复、合法内部回调、普通类不变、并发发布、线程保护、320 环境链与关闭全部通过，退出码 0。Owner 实际非法坐标/速度恢复、空位置与正常运动对象保留检查通过。`test` 无源，实际回归由既有 check 任务执行。

最终 JAR **1,527,412 字节**，**95 个业务类**及既有模块描述，无测试类、测试 DLL、脚本或日志。SHA-256：`45E0413C55C5DD7193EFC7FFD16612AEE7C2F2C9C173D9F27B0A9872BA7FC456`。安装目录 r17-fix1 摘要仍为 `ED887CC74D64C200541EE1FAA4EFD776961C446D1D4B7B0BF5E9DBEE3271C65A`。本轮未部署、未启动游戏、未提交推送；r18 的实机攻防、FPS 和保存退出未验收。

第三部分尚未整批完成：更早引导需要确认早于现有入口且依赖/目录可用的具体时序；异常强退需要区分合法关闭与攻击的可信入口；监听器/任务复活源解绑需要证明目标专属注册关系；额外混淆需要独立验证 JNI、反射和 ASM 稳定性。本批未猜测这些边界、未增加全局退出拦截或广域清理。既有已验证的目标静态引用、SavedData/BossBar 清理保留。


## r19 渲染去重、换世界清理与凭据存储（2026-11-06）

起止 HEAD 均为 `a8b0bef`。用户提供的审查针对旧 `80e508c`，本批以当前 r18 为准逐项核对，仅修改自身既有文件。r13 攻击/挥击入口逐字节不变，没有新增生产 Java 类型、依赖或网络协议。

- **绘制闭环**：Forge 正常绘制及批次提交成功后记录本帧完成；Native 仅在缺失或失败时补画。嵌套 Swap 不重复回调，帧缓冲绑定/拷贝阶段不再重复绘制 Avatar；前缓冲补画先询问必要性，正常帧跳过相关 GL 状态查询。失败保留最终补画机会，死亡渲染原有阶段保留，绘制异常时仍恢复 GL 状态。删除旧投影矩阵捕获与空 RenderCallbacks 分派。
- **世界身份**：r18 已有按 Level 身份隔离及更新去重，并非每次都会重复推进 Avatar。此次将客户端卸载的 Avatar/proxy/帧状态清理直接接入 Level.Unload，覆盖注册表记录已缺失的情况；旧世界延迟卸载不得清空新世界。同世界重复 spawn 保留既有运动状态，不把重复存在通知当成传送指令。
- **Remember Me**：仅持久化当前用户 DPAPI 加密的 refresh token，密码不再落盘；旧 password 项在读取时移除且不自动复用。账户绑定、令牌续期轮换、忘记登录、损坏密文拒绝和原子替换在既有验证文件内闭环，非等待文件锁避免并发忘记/新登录被旧续期覆盖。保留原有服务端票据与刷新验证规则。DPAPI 提供静态存储保护，不隔离同一 Windows 用户权限下的恶意进程或当前 JVM 内代码；本地测试模式不走真实账户验证界面，本轮没有读取用户 Secret.ini 或联系认证服务。
- **结构收敛**：删除无调用的 ModClassIndex、未安装的 RuntimeHooks，以及空 RenderCallbacks、RenderContext/Kind、旧 SecretRenderState，共减少 6 个业务 class。完成位合入现有 NativeRenderBridge；删除打包校验中已失效的 RuntimeHooks 专属断言，保留其余校验。
- **层级元数据**：BytecodeHierarchy 按 ClassLoader 弱引用身份共享不可变头信息，不缓存缺失；实际转换输出 ClassNode 更新对应头信息。三个写出入口同步迁移。缓存不持有加载器强引用，不在缓存锁内读取类资源，没有新增运行期扫描或重转换心跳。

本轮 Java 实际编译完成；最终完整构建复用该编译产物，生产 Native 实际重编。首次凭据检查对 DPAPI 元数据头部翻位不足以构成认证载荷损坏测试，改为破坏实际认证数据后，保留损坏拒绝断言重新通过。最终 `build checkNativeStartup -PsmokeJava=<PCL同款Java> --offline --console=plain --no-daemon` 成功：73 秒，27 项任务（17 执行、10 复用）。

实际执行通过：Forge 登记、桥接、Java 退出、既有目标守卫回归、新增绘制完成/兜底状态、换世界与卸载、加载器身份隔离/元数据复用/晚到定义检查；凭据检查使用合成账户与 build 目录内文件，覆盖用户 DPAPI、无明文、旧密码退役、轮换、账户绑定、损坏与忘记、并发写锁，无网络。`checkNativeShutdown` 正常、调用超时与引用读者超时三场景通过；`checkNativeStartup` 在独立 PCL 同款 JVM 加载生产 DLL，通过包绑定、自身基线、并发回调、线程保护、320 个 JVMTI 环境及关闭，进程退出码 0。标准 test 任务无测试源，实际回归由上述 check 任务执行。

最终包 `build/libs/Secret-4.3-local-test-r19.jar`：**1,520,308 字节**，**89 个业务类**及既有模块描述；SHA-256：`7093E0CD56B4B644DEC2D15EE162B0E53467F603D95EE67DAE9864B97CC3F659`。无测试类、测试 DLL、验证脚本或日志。已安装 r17-fix1 摘要未变，原有未跟踪 CFR 文件保留。

静态上移除了重复绘制、无用矩阵分配和重复类资源解析，但本轮没有启动 Minecraft、测量 FPS 或验证真实 GL/换维度画面；不将模型检查等同于实机通过。未部署、未提交或推送。


## r20 Java 缺口修补（2026-11-06）

以 r19 未提交工作区为基线，起止 HEAD 均为 `a8b0bef`；保留既有修改与未跟踪 CFR 文件。仅修改既有 Java、版本、检查和本文；Native 生产源码的完整 Git 差异摘要与起始值一致。r13 攻击/挥击文件 SHA-256 仍为 `05F0CA04266AA07F7B38487908EE880F057CDB586D40531BF9049D3DC843974F`。

- **Owner 运动**：登记时只采集合法标量；维护时要求绑定仍有效、同世界、非正常生命周期且非死亡处决。补齐两组旧坐标的非有限值，以及空、非有限或反向碰撞箱；只修复非法分量，异常碰撞箱按当前姿态尺寸重建。合法插值、碰撞箱对象和体型保持不变，无新增正常路径集合分配、会话鉴权或锁。
- **事件异常**：普通分派失败时只补跑 Tick END、世界卸载和实体离界的既有维护；失败登录/Clone/渲染不补发成功处理。保留 Forge 异常处理器及首个异常，次生异常附加，VirtualMachineError/ThreadDeath 直接抛出。正常分派顺序与取消状态保持原行为。
- **动态桥接**：删除生成类公开 bind 入口，不再接纳同名预加载类；现有安装器核对实际 Class/加载器、句柄来源与类型，以私有 volatile 数组完整发布两个句柄。重复安装复用本次 Class，绑定槽被替换明确报错；两个 post 描述符不变。该修改不等于防住任意反射/Unsafe 字段篡改，动态类 SourceShield 保护仍属后续 Native 范围。
- **节区与界面**：EntitySection.add 统一使用现有实例/同维度 UUID 拒签规则，保留 Owner、Secret 及正常新召唤。Owner 死亡界面守卫放在既有 DeathExecutionHooks，避免公共 OwnerSafetyHooks 的方法表新增客户端类型；只阻止有效 Owner 被强塞原版死亡界面，保留处决、普通菜单和正常生命周期。EntitySection 与客户端 Minecraft 加入一次定向重转换，新入口加入必检审计；不修改 r13 文件或恢复全 JVM 扫描。
- **监听器清理边界**：处决线程只查原始注册键 `key == target`，仅摘除可确认独占且按对象身份比较的分派监听器；共享回调、自定义相等语义与变化中的登记不猜测。Forge 对象索引依赖 Entity.equals/hashCode，空索引键本批保留并报告 partial，沿用原三次有界重试；因此可能仍保留目标引用，不能称为完全释放或完整断根。没有清空目标字段，也不扫描 Lambda 捕获、共享任务池或在 EventBus.post 添加清理扫描。
- **补画**：FOV 改为初始化时解析的 MethodHandle.invokeExact，保持实际 GameRenderer/Camera/float/boolean → double 签名和失败补画语义；r19 去重与 GL 状态恢复保留。

新增及既有 Java 回归通过：异常旧坐标、空/反向/非有限碰撞箱与合法对象保留；生命周期、异世界、失效绑定及死亡优先；事件首因/次生异常、致命异常、正常取消、维护事件选择；私有完整绑定、错误句柄、重复安装及同名定义冲突；节区同 UUID 新 ID、正常新 UUID、跨维度与 Owner/FakePlayer/Secret 分流；真实方法织入、Owner 界面与原死亡行为、同 ID 不同对象的监听器隔离及共享回调保留；FOV 实际目标类型、既有渲染/层级缓存检查。模型未执行真实 OpenGL 绘制。

首次完整构建实际编译 Java 和配套 r20 Native DLL，并实际执行 Native 退出正常、调用超时、引用读者超时三场景，均通过。新增夹具先后修正普通 JVM 缺少 Forge 事件父类准备、重复使用同一事件实例导致阶段冲突；没有修改生产断言或削弱保护。一次定点重跑被 ForgeGradle 联网证书预检阻断，独立 HTTPS 检查正常后，仅离线构建命令增加 `-Dnet.minecraftforge.gradle.check.certs=false`；始终保留 `--offline` 使用缓存，未修改工程/生产 TLS 设置。

最终 `.work/r20-final-build2.log`：`build checkNativeStartup -PsmokeJava=<PCL同款Java> --offline --console=plain --no-daemon`（含上述单次预检参数）成功，26 秒，27 项任务（13 执行、14 复用）。最终 Java 重编，Native 复用本批已生成 DLL；Native 退出模型和凭据检查复用本批已通过结果。生产 DLL 在独立 JVM 实际完成包绑定、84 个认证业务类、SourceShield、并发回调、线程保护、320 环境链和安全关闭，ExitCode=0。标准 test 无源，实际回归来自 check 任务。测试总线 shutdown 输出的 FATAL 栈是 Forge 自带诊断，两个模型总线均按预期关闭，不是游戏崩溃。

最终 JAR **1,528,306 字节**，**89 个业务类**及既有模块描述；SHA-256：`907BFB8A413A6345162EEB3DD4592D505AC9EF8B10964813A08D74A78888472C`。无测试类、测试 DLL、脚本或日志入包，安装目录 r17-fix1 摘要未变。源码静态上减少了补画反射装箱，新增正常检查有有限分支/查询成本；没有进行 FPS、真实攻防、界面操作或保存退出实机验收。本轮未部署、未启动 Minecraft、未提交推送。


## r21 Native 映像边界与必要入口核对（2026-11-06）

基线 HEAD 为 `7a97dd1`，本轮结束 HEAD 未变。仅调整既有 `late_recovery.cpp`、Native 检查、构建接线和本记录；保留原有未跟踪的 CFR 工具。Java 生产源码、r13 攻击/挥击入口及 r20 行为未修改。

- **映像边界**：在既有 DiskImage 内校验 DOS/NT/可选头、节表、目录、真实文件数据、展开表与重定位块。请求必须完整位于对应节的文件数据内，拒绝虚拟零填充、跨节、溢出、不可读或不匹配的映像。实测 Windows 加载头的 ImageBase 可变为实际地址；只允许磁盘首选地址或当前模块实际地址，其余头和节表继续逐字节核对，不用宽泛忽略字段绕过检查。
- **函数范围**：删除固定 64 字节恢复兜底。有展开表时只接受有效的精确入口，单区段上限 64 KiB，不合并分散代码块。无展开表时复用 MinHook HDE64，在最多 256 字节、64 条指令内跟踪可达分支，拒绝调用、循环、间接跳转、指令内部跳转和越界；只核对/修复可达指令，不覆盖中间空洞。经用户批准，允许直接尾跳到同一映像内具有有效 .pdata 的精确入口，目标单独核对且不新增修复权限。
- **写入与失败**：指针槽位使用对齐的原子更新；代码映射、分段原页面保护、写入长度、指令缓存刷新、保护恢复和读回均须成功。未改字节同样必须处于有效可执行映射。关键导出核对失败立即返回，禁止继续调用；函数或表失败不发布替代分派状态。保留一致、已恢复、范围不支持、失败四种结果，不把跳过算通过。
- **真实依赖入口**：按本地 JDK 17 jni.h 的实际 V/A 分派核对固定接口清单，增加 37 个 JNI 与 9 个 JVMTI 函数体检查；按槽位和实际地址去重，并在同次核对内复用尾目标结果。新覆盖函数发现差异只报告失败，不擅自改写。旧入口继续使用受上述范围约束的恢复流程；三个 late_recover_* 外部签名未变。

完整构建 `.work/r21-final-pcl.log` 成功：43 秒，27 项任务（16 执行、11 复用）。Java 生产代码未变，复用既有编译产物；r21 生产 DLL 本轮实际编译。Forge 登记、桥接、Java 退出、r16/r20 目标守卫与最终包校验实际通过；凭据模型本次复用已有通过产物，标准 test 仍为 NO-SOURCE，不冒充另有单元测试集。

`checkNativeShutdown` 本轮实际执行生产解析/写入模型及正常排空、调用超时、引用读者超时三个独立退出场景，均通过。新增夹具覆盖截断头、RVA/节边界、展开信息、有限分支与尾跳、非法重定位、原子指针、分段保护恢复及写入/刷新/读回失败；只改写自有测试缓冲区，不为检查改写正在运行的 JVM 代码。独立检查可执行文件及 HDE 检查对象不进入游戏包。

最终 DLL 分别由 Temurin 17.0.15+6（构建 JDK）和 Microsoft 17.0.15+6-LTS（PCL 所用 Java）执行 `checkNativeStartup`，均实际通过且 ExitCode=0。构建 JDK 最终记录 `.work/r21-final-jdk.log`：17 秒，20 项任务（6 执行、14 复用），生产 DLL 复用上次编译；PCL Native 现场保留于 `.work/r21-pcl-native.log`。日志确认三表核对、包绑定、84 个认证业务类、SourceShield、线程保护、并发回调、320 环境链及正常关闭。早期严格校验先后拒绝加载头地址差异及合法尾跳结构，定位并按批准边界修正后通过，没有把失败改记为通过。

构建命令保持 `--offline`，沿用命令级 `-Dnet.minecraftforge.gradle.check.certs=false` 避免 ForgeGradle 的联网证书预检；未修改工程或生产 TLS 配置。实际发布物仍含模块描述及唯一生产 himitsu.dll，无检查类、测试 DLL、脚本或日志。r13 文件 SHA-256 仍为 `05F0CA04266AA07F7B38487908EE880F057CDB586D40531BF9049D3DC843974F`。

本批不增加毫秒级巡检或周期性重转换，也没有增加游戏帧/Tick 调用。保留原私有候选与退避恢复机制；完整的并发函数体热修复仍属后续工作，不能由本轮范围验证推导任意运行中篡改均可安全恢复。实机画面、攻防、FPS 和保存退出均未执行。

最终 JAR：`build/libs/Secret-4.3-local-test-r21.jar`，1,556,688 字节，89 个业务类，小于 2 MB。SHA-256：`E5FB61CD8777BA4EFDEBCFD29422C5D52CF9927AD82039346458E7C5B217B24B`。

## r22 第三部分：安全恢复与动态桥接闭环（2026-11-06）

以 r21 未提交工作区为起点，起止 HEAD 均为 `7a97dd1`。原有五个未提交文件继续保留，起始差异另存 `.work/r21-before-r22.patch`；未跟踪的 CFR 工具未动。本批在既有文件内实施，未新增生产 Java 类型、线程、外部库或网络协议；第 4、5 部分没有混入。本地游戏 mods 目录仍为 r20，本轮没有部署。

### 生产修改与旧路径退出

- **统一核对与写入边界**：模块守护复用 r21 的 PE、展开表、有限分支及精确尾跳转规则。补齐命名/序号导出与有界转发；代码基线按实际区段地址去重，共享尾区段只登记一次。指针槽核对分配归属与当前值后 CAS 更新；生产调用不再直接回写活动 JVM/系统函数体。关键未恢复状态传播至 Native 就绪/命令和恢复入口，不继续用失败结果发布分派。
- **模块守护**：移除固定 16 字节导出快照、通用可执行区域写回、整表 memcpy 与 Sleep(1) 巡检。改为可停止事件唤醒的 250ms 固定清单，登记变更时发布新快照；常态只持有快照，不复制整个注册表。无变化的已登记项不读盘、不输出日志。确定不支持的函数形态按模块身份暂存；读取/映像核验失败或缺少转发目标继续有界退避，避免永久记住临时失败。
- **自有 Hook**：MinHook 保存并提供实际补丁区、patchAbove、跳板和 relay 的生成字节与长度；替换原先 target−5、16/64 字节猜测。磁盘基线与本次自有补丁分别核对，自有补丁之外的字节仍受检查；MH_ERROR_ENABLED 不再当作完整性证明。IAT 单独按槽位处理。启用过的跳板与原函数指针退出时保留；活动代码损坏且无法证明安全时明确拒绝覆盖。
- **本轮发现的真实旧路径**：首次真实 DLL 检查发现 DisposeEnvironment 仍被自身的 `31 C0 C3` 补丁改写，并非外部 Mod 故障。继续定位到 Instrumentation 的五个入口使用同类写法，现均迁移至 MinHook，按本机 JDK 原声明匹配参数，保留原拦截行为并接入统一期限关闭；没有增加新的 Attach/进程拦截能力。旧短补丁实现和整段导出恢复豁免已删除。
- **回调与生命周期**：回调函数本体使用可信映像范围核对；自身已从模块列表隐藏时，仅自身真实映像允许通过映射文件路径读取基线。模块引用、退役登记与在途读者保留到安全时点；表更新先停止相关检查并排空读者，JNI/JVMTI 和页面操作均在注册/引用锁外。停止唤醒事件保留至进程退出，避免晚到通知命中复用句柄。
- **动态事件桥接**：安装器身份来自已认证载荷和实际游戏加载器，只在安装/复核冷路径核验调用者。定义前登记精确类名、加载器与不可变字节，定义后绑定真实 Class；抢占同名类不接纳，失败按代次回滚。同名异加载器不受该动态基线影响，不扩大为整个 Forge 包。
- **句柄状态**：Native 分别保存两个合法 MethodHandle 引用，删除 Java 重复的 bound 真值。现有 JVMTI 守护线程每 250ms 检查数组类型、长度和元素身份；异常才构造完整数组并一次发布。新增引用沿用 r17 的快照读者与延迟 DeleteGlobalRef。两个 post 签名及普通事件分派行为保持不变，无新增逐次 post JNI 或查栈。新增实际使用的 JNI/JVMTI 函数同步进入固定核对清单。

### 本轮检查结果

- Java 和 r22 配套生产 Native DLL 本轮实际编译。最终完整构建 `.work/r22-final-build.log` 成功：55 秒，27 项任务（17 执行、10 复用）；Java 生产编译在此前本轮完成，最终复用，Native 本次重编。Forge 登记、包绑定、桥接、Java 退出、r16/r20 目标守卫和最终包校验通过；标准 test 为 NO-SOURCE，实际回归来自既有 check 任务。
- `checkNativeShutdown` 实际通过：生产 PE/范围/转发序号与循环逻辑、私有测试缓冲区的恢复与失败、CAS 冲突及错误分配归属拒绝、MinHook 普通/patchAbove 真实范围、共享地址去重、自有补丁外字节变化拒绝、在途退役、模块引用保留/释放、250ms 等待参数、登记唤醒和停止唤醒。正常排空、调用超时、引用读者超时三个旧场景继续通过。最后补充模型记录为 `.work/r22-final-model2.log`；最终完整构建也实际重跑了这些模型。
- 生产 DLL 的正常独立启动分别通过 Temurin 17.0.15+6 和 PCL 所用 Microsoft 17.0.15+6-LTS，均 ExitCode=0。最终 PCL 记录 `.work/r22-final-pcl2.log`：17 秒，20 项任务（6 执行、14 复用），复用同一生产 DLL。动态桥接真实安装、非法登记者拒绝、重复安装、数组/元素修复、字节码重定义恢复、异加载器隔离及并发复核均通过；三表、线程保护、320 个环境链与正常关闭继续通过。
- 独立抢占定义进程 `.work/r22-final-conflict.log` 本轮实际通过，ExitCode=0，确认不接纳预先定义的同名类并回滚登记；该检查在最终导出失败缓存分类微调前执行，动态桥接生产源码此后未变。最终缓存分类改动后重新跑通上述两套 Java 正常启动。
- Native 故障注入限于检查进程自己的内存和夹具映像；Java 字节码改写限于本工程检查类/桥接类。没有为检查改写运行中 JVM 的原生函数。事件总线 shutdown 的 FATAL 栈属于 Forge 模型诊断，检查进程正常退出，不能当作游戏崩溃。

### 明确的未覆盖与实机边界

本机独立启动中 `gdi32!SwapBuffers`、`user32!EnableWindow` 未通过当前完整范围/映像核验，保持 UNVERIFIED_RANGE_OR_IMAGE，未盲目写回。`msimg32!AlphaBlend` 与 `GLFW!glfwCreateWindow` 当时模块未加载，记为 WAITING_FOR_MODULE，保留晚到登记。自有 Hook 的补丁/跳板一致性与完整原函数范围是不同检查，不把前者当成后者通过。

本批完成的是用户选定的“可证明范围内恢复”，没有实现任意并发本机代码修复，也不保证任意内存破坏后进程仍可继续运行。静态上减少了巡检唤醒与重复扫描，并移除危险写入；未测量 FPS、实机攻防、画面、换世界或保存退出，不宣称实际提速。本轮未部署、未启动 Minecraft、未提交或推送。

最终包 `build/libs/Secret-4.3-local-test-r22.jar`：**1,572,992 字节**，**89 个业务类**，保留模块描述，低于 2 MB。仅含生产 himitsu.dll，未打入检查类、测试 DLL/EXE、脚本或日志。SHA-256：`E750FAAAB0769061A90C6B3952C162CD0948E1D449D3571DF7E4F309731F08F5`。r13 攻击/挥击文件 SHA-256 仍为 `05F0CA04266AA07F7B38487908EE880F057CDB586D40531BF9049D3DC843974F`。


## r23 第四部分首批：精准清理与来源解绑（2026-11-06）

起止 HEAD 均为 `7a97dd1`，以 r22 未提交工作区继续，原 28 个已修改文件和未跟踪 CFR 保留，起始差异存于 `.work/r22-before-r23.patch`。本批仅调整既有 TargetCleanup、EventBusTakeover、TargetGuardCheck、构建接线和本文；没有新增生产文件、类型或协议。Native 源码差异摘要与起始值一致，r13 攻击/挥击摘要保持 `05F0CA04266AA07F7B38487908EE880F057CDB586D40531BF9049D3DC843974F`。

- **精确引用与旧逻辑退出**：静态字段沿实际类层级只访问一次，删除重复继承扫描；不可访问字段保留为未知。移除“包装器直接引用目标就删除整个包装器”的通用判定，保留包装器及其他成员，仅按原边界断开可写的精确目标引用。补齐目标作为 Map 键的处理，核对键、值和标准容器；拒绝共享记录、变化中的引用及可变实体 ID 导致的相等歧义。并发 Map 使用值身份核对，未知容器保留，不建立同步代理。
- **监听器**：仍仅摘除原始登记键就是目标的独占分派监听器；同源 Lambda/内部类捕获只能形成候选，不能授权注销。区分分派摘除与原始索引残留，稳定残留不再反复重扫。普通 post 路径未修改。独立启动检查发现新方法签名提前解析未加载 Cleaner，已将既有冷路径上下文移出早期反射方法签名，不扩大加载或扫描范围。
- **任务**：仅从目标现有字段和实际类层级静态字段定位句柄/执行器。识别实际接收者就是目标的原生 FutureTask、RunnableAdapter 和 JDK 定时任务，使用 cancel(false)，仅移除同一队列对象；公共线程池和无关任务继续运行。自定义包装、捕获型 Lambda、不可读 JDK 字段保留；不加游戏 add-opens、不引入 Unsafe/Native 读取旁路，不中断已经执行的调用。
- **SavedData**：限定当前实际世界缓存及可确认同加载器、同来源的数据。只改精确实例关系与已有专用记录规则；SuperSteve NBT UUID 规则进一步限定实际 ssList 字段，不误删同文件其他 UUID 元数据。未知 UUID/历史记录不删除，发生修改才标脏，部分修改后发生异常仍保留正确脏标记。
- **重试与成本**：暂时并发变化沿用每 20 Tick、最多三次的既有重试；确定无法证明的对象保持 incomplete/exhausted，等待再次明确命中才复核。卸载清除对应状态与队列。没有新增每帧/每 Tick 全表扫描、查栈、JNI 或线程池巡检。处决冷路径增加有限来源/任务核对，未测量 FPS 或实际性能提升。

验收分级：

- 首轮实际编译 Java 和配套 r23 Native DLL，并执行 checkNativeShutdown：恢复范围、Hook 元数据、正常排空、调用超时、引用读者超时均通过。Native 生产源码未改，DLL 因 HSP3 版本绑定重建。首次新增任务夹具缺注册表初始化，修复夹具后保留原断言；随后修复上述真实早期加载依赖。
- 最终完整构建 `.work/r23-final-build.log` 成功：35 秒，28 项任务（14 执行、14 复用）。Java 重编，Native 与退出模型复用本轮已通过结果；Forge 登记、桥接、包绑定、Java/目标守卫回归和最终包校验通过。标准 test 为 NO-SOURCE，实际检查来自既有 check 任务及新增的独立任务访问场景。
- 默认检查 JVM 验证封闭 JDK 字段时保留；另一个仅用于检查的 JVM 开放 java.util.concurrent，验证准确接收者取消、公共池可继续工作及运行中任务不被中断。该开放参数只在 checkTargetCleanupAccess，不进入游戏运行配置或 JAR。
- 补充登记替换和世界卸载检查后，`.work/r23-final-guards2.log` 成功：46 秒，9 项任务（3 执行、6 复用）。覆盖同 ID 不同对象、共享包装/监听器、同 UUID 历史、异加载器/异来源 SavedData、已知记录回归、不可访问元数据、有限重试、再次命中和卸载。补充夹具的一处局部变量重名已修复；生产逻辑未再改变。
- 构建 JDK 与 PCL Java 的独立 checkNativeStartup 均 ExitCode=0；最终 PCL 记录 `.work/r23-final-pcl.log` 成功：28 秒，20 项任务（6 执行、14 复用），复用同一生产 DLL。包绑定、SourceShield、动态桥接重定义/句柄修复、并发回调、线程保护、320 环境链及正常关闭通过。检查总线 shutdown 的 FATAL 栈是 Forge 夹具诊断，不是游戏崩溃。

最终 `build/libs/Secret-4.3-local-test-r23.jar` 为 **1,585,040 字节**，**89 个业务类**，保留模块描述；SHA-256：`D88ACDE41B0E26CEA424B28EDFE84B9B43C41DB5D887361128BE5BD3AE91C8CD`。只含生产 himitsu.dll，未加入检查类、测试 DLL/EXE、脚本或日志。mods 目录仍为 r20，本轮没有写入部署目录。

本批不宣称所有未知复活来源已解绑：捕获关系不证明独占职责，不可读/自定义任务保持原行为，已执行回调不会被撤回，歧义索引可能仍保留目标引用。第 4 部分的退出、Attach/进程、低层线程、提前引导和发布期收敛不在本批。实机攻防、画面/FPS、存档与保存退出均未执行；未提交、未推送。
