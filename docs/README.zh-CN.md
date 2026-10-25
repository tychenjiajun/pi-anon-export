# pi-anon-export

[![npm version](https://img.shields.io/npm/v/pi-anon-export?color=7c3aed)](https://www.npmjs.com/package/pi-anon-export)
[![npm downloads](https://img.shields.io/npm/dm/pi-anon-export)](https://www.npmjs.com/package/pi-anon-export)
[![license](https://img.shields.io/badge/license-MIT%20%2B%20Apache--2.0-blue)](https://github.com/tychenjiajun/pi-anon-export/blob/main/LICENSE)
[![pi extension](https://img.shields.io/badge/pi-extension-7c3aed)](https://pi.dev/packages/pi-anon-export)

简体中文 | [English](https://github.com/tychenjiajun/pi-anon-export/blob/main/README.md)

**[pi](https://pi.dev) 扩展：把 agent 会话导出成匿名的 JSONL**，全程本地运行，任何内容都不会离开你的机器。适合要分享会话记录的场景——提 bug、发给同事、贴到公开 gist——同时不希望泄露 API key、token、cookie、邮箱或截图。

![pi-anon-export：会话文件脱敏前后](https://raw.githubusercontent.com/tychenjiajun/pi-anon-export/main/assets/preview.png)

## 安装

```bash
pi install npm:pi-anon-export
```

不安装、只在一次调用里试用：

```bash
pi -e npm:pi-anon-export
```

## 用法

```
/anon-export            导出「当前」会话（脱敏后的 JSONL）
/anon-export zip        导出当前工作目录对应的全部会话，脱敏后打包成一个 zip
```

![演示：会话文件 → 脱敏 → 结果 → 校验](https://raw.githubusercontent.com/tychenjiajun/pi-anon-export/main/assets/demo.gif)

### 参数（两种模式通用）

参数按 shell 规则解析：引号可以包裹带空格的值（`--secret "value with spaces"`），`--flag=value` 可用于以 `--` 开头的值。**缺少值是错误**（`--out --no-images` 不会创建一个叫 `--no-images` 的目录），空值也是错误（`--out ""` 不会悄悄变成当前目录）。

| 参数 | 作用 |
|---|---|
| `--no-images` | 把内嵌的图片/音频/视频数据块替换为 `[IMAGE_REMOVED]`。不加时图片**按字节原样保留**并计入 `images_flagged`，提醒你人工过一遍。 |
| `--level fast\|full` | 脱敏深度，默认 `full`。 |
| `--pii conservative\|aggressive` | `aggressive` 额外启用上游的「人名」「街道地址」模式。需要 `--level full`；`--level fast` 配 `--pii aggressive` 会被直接拒绝（fast 级别不跑 anonymizer，静默失效比报错更糟）。 |
| `--out <dir>` | 输出目录。默认：当前会话模式为 `./pi-anon-export-<时间戳>/`，zip 模式为当前目录。 |
| `--secret <字面量\|文件>` | 追加一个秘密字面量；若值是可读文件路径，则按「一行一个 secret」读取。可重复。 |
| `--env-file <路径>` | 用它**替代**默认的 shell rc 文件集合。可重复。 |

### 输出路径与隔离

- `/anon-export` → `./pi-anon-export-<时间戳>/<会话文件名>.jsonl`（或 `<--out>/<会话文件名>.jsonl`）
- `/anon-export zip` → `./pi-anon-export-<时间戳>.zip`（或 `<--out>/pi-anon-export-<时间戳>.zip`），整次运行共用一个时间戳

zip 是**边脱敏边写入**的：每个会话脱敏完立刻压进归档（先写 `<文件名>.<pid>-<随机>.part`，再 rename），所以整个项目的脱敏结果不会同时驻留内存；同一毫秒内的两次运行也不会交错写同一个文件。重复的条目名会被拒绝，空会话或完全无法解析的会话会被报告为「跳过」，而不是产出一个 0 字节文件。

输出使用私有权限：目录 `0700`、文件 `0600`、归档 `0600`（即使目标位置已存在旧文件或旧的 `.part`，也会被重新收紧）。如果某个会话在脱敏后仍能匹配到已知秘密，它**不会**以正常文件名落盘，而是被隔离成 `<会话文件名>.jsonl.UNSAFE`（zip 模式为 `pi-anon-export-<时间戳>-UNSAFE.zip`），非交互运行（print/JSON 模式）以非零码退出——脚本无法把「仍然泄露的导出」当成干净结果。若输出路径解析后就是源会话本身（包括通过软链接、硬链接指向它），会直接拒绝，避免覆盖 pi 正在写入的实时会话。

报告会给出：导出的会话数、输出路径、脱敏计数（替换的秘密数、删除/标记的图片数、丢弃的行数、anonymizer 各类计数）、被忽略输入的说明、以及脱敏后校验的结果。无 TUI（print/JSON 模式）时报告走 **stderr**，保持 stdout 干净。

### 示例

```bash
/anon-export
/anon-export zip --no-images
/anon-export --level fast --out /tmp/shareable --secret "my-personal-token"
/anon-export --env-file ./.env --env-file ~/.zshrc
```

## 脱敏分级

每次导出都跑同一条基础流水线（逐行处理 JSONL）：

1. **解析或丢弃（fail-safe）**：不是合法 JSON、或不是 JSON 对象的行会被**丢弃并计数**（`dropped_lines`），永远不会原样透传。
2. **媒体处理**：只有「字节自己表明身份」或「上下文说明了身份」的 >256 字符字符串才算内嵌图片/音频/视频——媒体专用键（`b64_json`、`imageData`、`image_data`、`audioData`、`videoData`、`fileData`、`contentBytes`）、父对象声明了 `type`/`mimeType`/`mediaType` 的 `data`/`base64`/`blob` 值、任意键下的 `data:image/…` URL、或可识别的容器魔数（`iVBOR`、`/9j/`、`R0lGOD`、`UklGR`、`GkXf`、`ftyp`）。声明的 MIME 类型**只覆盖它旁边那个载荷键**；文本型媒体（`image/svg+xml`、`text/*`、`*json`）一律按文本脱敏，因为它们的内容是散文。被保留的载荷不会被任何一步改写（包括 anonymizer），因为任何编辑都会破坏图片。
3. **秘密字面量一次替换**：每个已发现秘密的所有出现都变成 `[REDACTED_<名字>]`。秘密来源：
   - shell rc 文件里的 `export NAME=...` / `declare -x NAME=...` 行（`~/.zshenv`、`~/.zprofile`、`~/.zshrc`、`~/.zlogin`、`~/.bash_profile`、`~/.bashrc`、`~/.profile`），或你用 `--env-file` 指定的文件。文件按 shell 的 source 顺序读取，所以**最终生效的值**会被采用；同名变量被定义成不同值时只告警变量名（绝不打印值）。变量名必须包含 `KEY`、`TOKEN`、`SECRET`、`PASS`、`PWD`、`COOKIE` 或 `CREDENTIAL`；
   - 你传入的每个 `--secret`（字面量或文件，一行一个，容忍 BOM/CRLF）。

   值的读取方式与 POSIX shell 一致，因此秘密不会被悄悄截断：引号段一直读到匹配的收尾引号并与未引用段拼接（引号内的 `#` 属于值，`\"` 会被解转义），未引用的值在 shell 空白处结束（以 `#` 开头的词保留 `#`：`pa#ss123`），`\` 续行先合并，`if` 块里缩进的行同样会被扫描，`NAME+=value` 会同时登记追加文本和拼接后的完整值，未闭合的引号则保留剩余内容。短于 5 个字符的值会被拒绝；可能匹配到 `[REDACTED_…]` 标记内部的值（例如 `REDACT`）也会被拒绝——两种情况都给出不含值的说明，而一个**包含** `[REDACTED_` 的长秘密会正常脱敏。每个值同时按 NFC 与 NFD 两种拼写匹配。

然后在基础流水线之上按级别叠加：

- **`fast`**：到此为止。只有结构丢弃、图片策略、秘密字面量。路径、用户名、邮箱、时间戳**不动**。
- **`full`**（默认）：再把每个剩余的叶子字符串交给 **anonymizer**（邮箱 → `redacted-<hash8>@example.com`、家目录用户名、code-host URL 用户名、API key、JWT、Bearer token、带凭据的 URL、query 里的秘密、私钥块、SSN/电话/IP）。一次导出运行内共享同一个实例，同一输入永远映射成同一输出，一致性可回读。`--pii aggressive` 再追加人名与街道地址。**没有大小上限**：1 MiB 的工具输出同样跑完整流程，且各处守卫按匹配数线性（一整份 1 MiB、塞满邮箱的 git log 约 0.1 s）。

最后，**每个文件在拿到可分享的名字之前**都会再跑一次校验：重新扫描所有已知秘密字面量（原始形式**和** JSON 转义形式），报告 `Verified: no known secret literal remains`，或一个醒目的 `✖ VERIFICATION FAILED`。失败的文件写成 `*.UNSAFE` / `-UNSAFE.zip`，非交互运行以非零码退出。

zip 里附带 `manifest.json`：每个文件的源名字、脱敏内容的 sha256（直接用写进归档的字节计算）以及**逐文件**脱敏计数；还有 `verification.residualSecrets`（必须为 `0`）与 `verification.secretSet`——被应用秘密集合的**加盐**指纹，不含值，盐每次运行随机，所以两次导出无法互相串联。指纹是「一致性检查」，不是保密手段（盐就写在 manifest 里）。manifest 里的跳过项会被**消毒**：只保留 basename（pi 的会话目录名里含本机用户名和项目路径），fs 错误信息也会被改写，不重新引入绝对路径。

## 隐私：完全本地

本扩展**没有任何网络 I/O**。它读取会话文件和 env 文件，把结果写到输出目录，除此之外什么都不做：没有遥测、没有上传、没有模型调用。唯一的运行时依赖是 [`fflate`](https://github.com/101arrowz/fflate)（纯 JS zip），只在 zip 模式的本地使用。

## ⚠️ 免责声明：脱敏是尽力而为

**脱敏是启发式规则，不是保证。** 发布或分享之前请人工检查导出内容。不符合命名启发式的秘密、未知标识符、anonymizer 不认识的 PII 模式都可能残留。作者不对导出文件中残留的信息承担任何责任。

以下是**有意为之**的行为（`extensions/lib/anonymize.ts` 中有完整记录）：

- 含 `/` 的文本片段会被当作路径，其中的 `user@host` 形状会被**保留**（与上游 Teich 的守卫一致）；URL userinfo（`https://user@host/…`）同样保留。
- 公开 git remote、保留示例域、systemd unit（`x@y.service`）、包版本（`lodash@4.17.21`）会保留。
- `dir\name@foo.com` 这种反斜杠分隔的串会被**过度脱敏**（邮箱形状的尾部被替换）：宁可误杀，不可漏放。
- code-host URL 里的用户名（`git:github.com/<user>/…`、`git@github.com:<user>/…`、`https://github.com/<user>`）只在该用户名已经在家目录路径或邮箱 local part 中出现过之后才改写。
- 图片默认保留并标记人工确认；`--no-images` 才会删除。截图不做 OCR，所以**保留的图片载荷里**若出现已知秘密无法被替换——校验环节会抓到，并把导出隔离为 `*.UNSAFE`。
- 秘密发现刻意收窄：只读上面那些 shell rc 文件（或 `--env-file`）里的 `export NAME=value` 行。项目里的 `.env`、`~/.aws/credentials`、`~/.npmrc`、`~/.netrc`、Windows PowerShell profile **都不会读**，除非你用 `--env-file` 指过去；在意的值请同时用 `--secret` 传。
- 人名与街道地址只在 `--pii aggressive` 下脱敏；SSN、电话、IP 在 `full` 级别始终脱敏。
- anonymizer 认识的是**通用的**凭据形状，不认识你雇主的内部 ID 格式。
- 校验只能检查「给它的那些秘密」：秘密集合为空时，报告会明确说「没有可比对的东西」，而不是宣称成功。
- 代码比较（`password == "x"`、`=>`）从不被当作赋值，所以比较右侧的字符串不会被脱敏（这一点与上游一致，上游会把它们误当赋值）。
- 非 ASCII 域名（IDN）、以点开头的 local part 的邮箱不会被识别；紧贴前一个单词字符的地址（`...alice@x.io`）保持原样。域名带 `_`、带 `+tag`、带端口、带标点的地址可以识别；local part 按 RFC 限制到 64 字符，这也正是邮箱守卫在大文本上保持线性的原因。
- 密码里含未转义的 `/ ? #` 的凭据 URL（`postgres://user:pa/ss#x@host`）在常见数据库/邮件 scheme 下能被覆盖；其他 scheme 下密码止于 URL 的 authority，未转义的尾部可能残留。反之，**没有**凭据的 URL（`https://host:8080/path?a=b@c.io`）绝不会被误当作凭据 URL。
- `typeset` 不支持（只支持 `export` / `declare -x`）。

## 常见问题

### 会有任何东西离开我的机器吗？

不会。扩展**完全没有网络 I/O**：没有遥测、没有上传、没有模型调用。它只读会话与 env 文件、写导出结果，然后结束。

### 这和直接拷 `~/.pi/sessions/` 里的 JSONL 有什么区别？

那些 JSONL 里留着 agent 见过的一切：shell rc 里的秘密、同事邮箱、家目录路径、base64 截图。`/anon-export` 会逐个叶子重写（秘密 → `[REDACTED_<名字>]`，邮箱 → `redacted-<hash8>@example.com`，家目录 → `user_<hash8>`），丢弃无法解析的行，再在交付一个可分享名字之前重新扫描一遍所有已知秘密。

### 万一脱敏失败会怎样？

文件不会以正常名字落盘：它变成 `<会话文件>.jsonl.UNSAFE`（或 `pi-anon-export-<时间戳>-UNSAFE.zip`），非交互运行以非零码退出。脚本无法把泄露的导出当成干净结果。

### 它到底能找到哪些秘密？

来自 `~/.zshenv`、`~/.zprofile`、`~/.zshrc`、`~/.zlogin`、`~/.bash_profile`、`~/.bashrc`、`~/.profile`（或 `--env-file` 指定的文件）中，变量名含 `KEY`/`TOKEN`/`SECRET`/`PASS`/`PWD`/`COOKIE`/`CREDENTIAL` 的 `export NAME=value` 行的字面量。此外 `full` 级别还认识通用凭据形状（API key、JWT、Bearer token、带凭据的 URL、私钥块）与 PII（邮箱、SSN/电话/IP、家目录路径）；`--pii aggressive` 再加上人名和街道地址。项目 `.env`、`~/.aws/credentials`、`~/.npmrc`、`~/.netrc` **不会**被读取，除非你把 `--env-file` 指向它们。

### 图片和截图怎么处理？

默认**按字节原样保留**并计数提示人工确认，因为任何改写都会破坏图片。加 `--no-images` 才会把识别出的媒体载荷替换为 `[IMAGE_REMOVED]`。文本型媒体（`image/svg+xml`、`text/*`、`*json`）始终按文本处理并脱敏。

### zip 可以直接分享吗？

zip 里有 `manifest.json`：逐文件 sha256、逐文件脱敏计数、以及 `verification.residualSecrets`（必须为 `0`）。跳过项被消毒成 basename，不会重新引入家目录或项目路径。但仍建议发布前读一遍导出内容——脱敏是尽力而为。

### 为什么会提示我在 git 仓库里？

zip 模式默认写到当前目录。如果那里是 git 工作树，报告会提示一句，因为提交一份会话记录只差一个 `git add -A`；把归档（或导出目录）加进 `.gitignore`。

### 支持很大的会话吗？

支持。**没有大小上限**：1 MiB 的工具输出同样跑完整流程，守卫按匹配数线性（1 MiB、塞满邮箱的 git log 约 0.1 s）。zip 模式是边脱敏边流式写入，不缓冲整个脱敏结果集。

## 会话位置

导出目标会话的定位方式与 pi 一致：

- 运行中的会话里优先用 `ctx.sessionManager.getSessionDir()` / `getSessionFile()`（它们已经遵循 `--session-dir`、`PI_CODING_AGENT_SESSION_DIR` 与 `sessionDir` 设置）；
- 否则用 `getAgentDir()`（遵循 `PI_CODING_AGENT_DIR`）加 `sessions/--<路径>--/`，其中 `<路径>` 是 cwd 去掉前导斜杠后把 `/`、`\`、`:` 换成 `-`。

相对路径的会话目录基于会话 cwd 解析，绝不基于 `process.cwd()`。

## 开发者：anonymizer 契约

`extensions/lib/anonymize.ts` 暴露 `full` 级别使用的扩展点：

```ts
export interface Anonymizer {
  anonymizeValue(value: unknown): unknown; // 有状态；同一实例内保持一致
  readonly counts: Record<string, number>;
}
export function createAnonymizer(options?: { aggressivePii?: boolean }): Anonymizer;
```

一次导出运行创建一个实例、跨文件共享，因此映射一致。`counts` 在实例上累计；`redactSessionJsonl` 每次调用前后取快照并报告**增量**，所以 manifest 里的计数是真正的逐文件计数。

`extensions/lib/secrets.ts` 提供 `createSecretMatcher()`（单次、最长优先的字面量替换）与 `computeSecretFingerprint()`（加盐、带长度前缀、与顺序无关）。

## 开发

```bash
pnpm install
pnpm run check   # tsc --noEmit
pnpm run smoke   # 离线冒烟测试：流水线、秘密、参数、zip、端到端 handler，
                 # 外加 scripts/hypothesis-smoke.ts（对抗式回归用例）
pnpm test        # check + smoke
```

冒烟测试是密闭的：`--env-file` 指向 `fixtures/`，所有导出都写临时目录，绝不会读你真实的 `~/.zshrc` 和会话。

## 链接

- 包主页：<https://pi.dev/packages/pi-anon-export>
- pi 包文档：<https://pi.dev/docs/latest/packages>
- 问题反馈：<https://github.com/tychenjiajun/pi-anon-export/issues>
- 上游 anonymizer 项目：<https://github.com/TeichAI/teich>

## 许可证

双许可，因为本包内嵌了一个 Apache-2.0 项目的移植：

- **MIT** — 本包中所有原创部分（见 [`LICENSE`](https://github.com/tychenjiajun/pi-anon-export/blob/main/LICENSE)）。
- **Apache-2.0** — `extensions/lib/anonymize.ts`，是 [`TeichAI/teich`](https://github.com/TeichAI/teich) `src/teich/anonymize.py` 的修改版 TypeScript 移植（见 [`LICENSE-APACHE`](https://github.com/tychenjiajun/pi-anon-export/blob/main/LICENSE-APACHE)；按 Apache-2.0 §4(b) 的要求，文件头逐条列出了所有偏差）。

`extensions/lib/secrets.ts` 是独立实现：只借鉴了 [`badlogic/pi-share-hf`](https://github.com/badlogic/pi-share-hf) 公开文档描述的**做法**（从 env 文件做字面量秘密脱敏）——该项目**不带任何许可证**，因此没有取用其代码。

[pi](https://github.com/earendil-works/pi) 的 API 类型通过 `peerDependency` 在运行时使用；pi 是 MIT，本包不打包任何 pi 源码。
