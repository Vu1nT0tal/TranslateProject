选题标题格式：

```
原文日期 标题.md
```

其中：

- 原文日期为该文章发表时的日期，采用 8 位数字表示
- 标题需去除特殊字符，标点只保留 `-`、`_` 等符号。注意文件名文字的编码格式。

正文内容：

```
[#]: collector: (选题人 GitHub_ID)
[#]: translator: ( )
[#]: reviewer: ( )
[#]: publisher: ( )
[#]: subject: (文章标题)
[#]: via: (原文_URL)
[#]: author: (作者名 作者链接的_URL)
[#]: url: ( )

标题
=======

### 子一级标题

正文

#### 子二级标题

正文内容

![图片说明][1]

*图片说明也可以放这里*

### 子一级标题

正文内容 ： I have a [dream][2]。

--------------------------------------------------------------------------------

via: 原文 链接 URL

作者：[作者名][a]
选题：[选题 ID][b]
译者：[译者 ID](https://github.com/译者 ID)
校对：[校对 ID](https://github.com/校对 ID)

[a]: 作者链接 URL
[b]: 选题链接 URL
[1]: 图片链接地址
[2]: 文内链接地址
```

说明：

1. 标题层级很多时从 `##` 开始
2. 图片链接和引文链接地址在下方集中写
3. 因为 Windows 系统文件名有限制，所以文章名不要有特殊符号，如 `\/:*"<>|`，同时也不推荐全大写，或者其它不利阅读的格式
4. 正文格式参照[中文排版指北](copywriting.md)
5. 我们使用的 markdown 语法和 GitHub 一致。而实际中使用的都是基本语法，比如链接、包含图片、标题、列表、字体控制和代码高亮。
6. 选题的内容分为两类：干货和湿货。干货就是技术文章，比如针对某种技术、工具的介绍、讲解和讨论。湿货则是和技术、开发、计算机文化有关的文章。选题时主要就是根据这两条来选择文章，文章需要对大家有益处，篇幅不宜太短，可以是系列文章，也可以是长篇大论，但是文章要有内容，不能有严重的错误，最好不要选择已经有翻译的原文。