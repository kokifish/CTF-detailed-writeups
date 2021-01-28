## 创建新仓库

创建新文件夹，打开，然后执行

`git init`

以创建新的git仓库



## 检出仓库

执行如下命令以创建一个本地仓库的克隆版本：

`git clone repository`

如果是远端服务器上的仓库，你的命令会是这个样子：

`git clone username@host:repository`

![image-20210124094437026](/Users/jackson/Library/Application Support/typora-user-images/image-20210124094437026.png)



## 添加和提交

你可以提出更改（把他们添加到暂存区），使用如下命令

`git add <filename>`

`git add *`

这是git基本工作流程的第一步；使用如下命令以实际提交更改：

`git commit -m “代码提交信息”`

现在，你的改动已经提交到了***HEAD***，但是还没有到你的云端仓库。

## 推送改动

执行如下命令以将这些改动提交到远端仓库：

`git push origin master`

可以把*master*换成你想要推送的任何分支。

如果还没有克隆现有仓库，并欲将你的仓库连接到某个远程服务器，可以使用如下命令添加：

`git remote add origin <server>`

如此就能够将你的改动推送到所添加的服务器上去了。

## 分支

创建一个叫“feature_x“的分支，并切换过去：

`git checkout -b feature_x`

切换回主分支：

`git checkout master`

再把新建的分支删掉：

`git branch -d feature_x`

除非你将分支推送到远端仓库，不然该分支就是不为他人所见的：

`git push origin <branch>`

## 更新与合并

要更新你的仓库至最新改动，执行：

`git pull`

以在你的工作目录中获取（*fetch*）并合并（*merge*）远端的改动。

要合并其他分支到当前你的分支（例如*master*）执行：

`git merge <branch>`

在这两种情况下，git都会尝试去自动合并并改动。遗憾的是，这可能并非每次都成功，并可能出现冲突（*conflicts*）。这时候就需要你修改这些文件来手动合并这些冲突。改完之后，你需要执行如下命令以将他们标记为合并成功：

`git add <filename>`

在合并改动之前，你可以使用如下命令预览差异：

`git diff <source_branch> <target_branch>`

## 标签

为软件发布创建标签是推荐的。可以执行如下命令创建一个叫做1.0.0的标签：

`git tag 1.0.0 1b2e……`

`1b2e`是你想要标记的提交ID的前10位字符。你可以使用`git log`获取提交ID。

## 替换本地改动

如果操作失误，可以使用如下命令替换本地改动：

`git checkout -- <filename>`

此命令会使用***HEAD***中的最新内容替换掉你的工作目录中的文件。已添加到暂存区的改动以及新文件都不会收到影响。

假如你想丢弃你在本地的所有改动与提交，可以到服务器上获取最新的版本历史，并将你的本地分支指向它：

`git fetch origin`

`git reset --hard origin/master`

## 实用小贴士

内建的图形化git：

`gitk`

彩色的git输出

`git config color.ui true`

显示历史记录时，每个提交的信息只显示一行：

`git config format.pretty oneline`

交互式添加文件到缓存区：

`git add -i`



