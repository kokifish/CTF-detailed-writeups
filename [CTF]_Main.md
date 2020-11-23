[TOC]





# Resource Index

- 知道创宇研发技能表v3.1 https://blog.knownsec.com/Knownsec_RD_Checklist/index.html 
- 漏洞银行 https://www.bugbank.cn/
- 







## 快速学习html语句

```html
html快速学习语句
一、文字
　　1.标题文字 <h#>..........</h#> #=1~6；h1为最大字，h6为最小字
　　2.字体变化 <font>..........</font>
　　【1】字体大小 <font size=#>..........</font> #=1~7；数字愈大字也愈大
　　【2】指定字型 <font face="字体名称">..........</font>
　　【3】文字颜色 <font color=#rrggbb>..........</font>
　　rr：表红色（red）色码
　　gg：表绿色（green）色码
　　bb：表蓝色（blue）色码
　　rrggbb也可用6位颜色代码数字
　　3.显示小字体 <small>..........</small>
　　4.显示大字体 <big>..........</big>
　　5.粗体字 <b>..........</b>
　　6.斜体字 <i>..........</i>
　　7.打字机字体 <tt>..........</tt>
　　8.底线 <u>..........</u>
　　9.删除线 <strike>..........</strike>
　　10.下标字 <sub>..........</sub>
　　11.上标字 <sup>..........</sup>
　　12.文字闪烁效果 <blink>..........</blink>
　　13.换行（也称回车） <br>
　　14.分段 <p>
　　15.文字的对齐方向 <p align="#"> #号可为 left：表向左对齐（预设值） center：表向中对齐 right：表向右对齐 P.S.<p align="#">之后的文字都会以所设的对齐方式显示，直到出现另一个<p align="#">改变其对齐方向，遇到<hr>或<h#>标签时会自动设回预设的向左对齐。
　　16.分隔线 <hr>
　　【1】分隔线的粗细 <hr size=点数>
　　【2】分隔线的宽度 <hr size=点数或百分比>
　　【3】分隔线对齐方向 <hr align="#">
　　#号可为 left：表向左对齐（预设值） center：表向中对齐 right：表向右对齐
　　【4】分隔线的颜色 <hr color=#rrggbb>
　　【5】实心分隔线 <hr noshade>
　　17.居中对齐 <center>..........</center>
　　18.依原始样式显示 <pre>..........</pre>
　　19.<body>指令的属性
　　【1】背景颜色 -- bgcolor <body bgcolor=#rrggbb>
　　【2】背景图案 -- background <body  background="图形文件名">
　　【3】设定背景图案不会卷动 -- bgproperties <body bgproperties=fixed>
　　【4】文件内容文字的颜色 -- text <body text=#rrggbb>
　　【5】超连结文字颜色 -- link <body link=#rrggbb>
　　【6】正被选取的超连结文字颜色 -- vlink <body vlink=#rrggbb>
　　【7】已连结过的超连结文字颜色 -- alink <body alink=#rrggbb>
　　20.文字移动指令<MARQUEE>..........</MARQUEE>
　　移动速度指令是:scrollAmount=#    #最小为1，速度为最慢；数字越大移动的越快。
　　移动方向指令是：direction=#          up向上、down向下、left向左、right向右。
　　指令举例：<MARQUEE scrollAmount=3 direction=up>..........</MARQUEE>
　　
　　二、图片
　　1.插入图片 <img src="图形文件名">
　　2.设定图框 -- border <img src="图形文件名" border=点数>
　　3.设定图形大小 -- width、height <img src="图形文件名" width=宽度点数 height=高度点数>
　　4.设定图形上下左右留空 -- vspace、hspace <img src="图形文件名" vspace=上下留空点数 hspace=左右留空点数>
　　5.图形附注 <img src="图形文件名" alt="说明文字">
　　6.预载图片
　　<img src="高解析度图形文件名" lowsrc="低解析度图形文件名"> P.S.两个图的图形大小最好一致;
　　7.影像地图（Image Map） <img src="图形文件名" usemap="#图的名称"> <map name="图的名称">
　　<area shape=形状 coords=区域座标列表 href="连结点之URL">
　　<area shape=形状 coords=区域座标列表 href="连结点之URL">
　　<area shape=形状 coords=区域座标列表 href="连结点之URL">
　　<area shape=形状 coords=区域座标列表 href="连结点之URL"> </map>
　　【1】定义形状 -- shape
　　shape=rect：矩形 shape=circle：圆形 shape=poly：多边形
　　【2】定义区域 -- coords
　　a.矩形：必须使用四个数字，前两个数字为左上角座标，后两个数字为右下角座标
　　例：<area shape=rect coords=100,50,200,75 href="URL">
　　b.圆形：必须使用三个数字，前两个数字为圆心的座标，最后一个数字为半径长度
　　例：<area shape=circle coords=85,155,30 href="URL">
　　c.任意图形（多边形）：将图形之每一转折点座标依序填入
　　例：<area shape=poly coords=232,70,285,70,300,90,250,90,200,78 href="URL"
　　三、表格相关
　　1.表格标题
　　<caption>..........</caption>
　　表格标题位置 -- align
　　<caption align="#"> #号可为 top：表标题置于表格上方（预设值）
　　bottom：表标题置于表格下方
　　2.定义列 <tr>
　　3.定义栏位 《1》<td>：靠左对齐
　　《2》<th>：靠中对齐ⅱ粗体
　　【1】水平位置 -- align <th align="#">
　　#号可为 left：向左对齐  center：向中对齐 right：向右对齐
　　【2】垂直位置 -- align <th align="#"> #号可为
　　top：向上对齐 middle：向中对齐    bottom：向下对齐
　　【3】栏位宽度 -- width     <th width=点数或百分比>
　　【4】栏位垂直合并 -- rowspan    <th rowspan=欲合并栏位数>
　　【5】栏位横向合并 -- colspan      <th colspan=欲合并栏位数>
　　四、表格的主要属性
　　1. <table>标记的主要属性
　　align定义表格的对齐方式，有三个属性值center，left，right
　　background定义表格的背景图案，属性值为图片的地址
　　bgcolor定义表格的背景颜色，属性值是各种颜色代码
　　border定义表格的边框宽度，属性值是数字
　　bordercolor定义表格边框的颜色，属性值是各种颜色代码
　　cellpadding定义单元格内容与单元格边框之间的距离，属性值是数字
　　cellspacing定义表格中单元格之间的距离
　　height定义表格的高度，属性值是数字
　　width定义表格的宽度，属性值是数字
　　2. <tr>标记，表格是由多行与多列组成的，<tr>标记用来定义表格的一行，他的属性极其属性值定义的是表格中的该行，其主要属性与属性值如下：
　　align定义对齐方式，属性值与上同
　　background定义背景图案 bgcolor定义背景色
　　3. <td>标记。用<td>标记概况起来的内容表示表格的单元。其主要属性与属性值和<table>标记的一样，补充两个合并列和行的代码：
　　colspan定义合并表格的列数，属性值是数字
　　rowspan定义合并表格的行数，属性值是数字
　　五、FRAME
　　1、分割视窗指令 <frameset>..........</frameset>
　　【1】垂直（上下）分割 -- rows
　　<frameset rows=#> #号可为点数：
　　如欲分割为100,200,300三个视窗，则<frameset rows=100,200,300>；
　　亦可以*号代表，如<frameset rows=*,500,*>
　　百分比：如<frameset rows=30%,70%>，各项总和最好为100%;
　　【2】水平（左右）分割 -- cols <frameset cols=点数或百分比>
　　2、指定视窗内容 -- <frame>
　　<frameset cols=30%,70%> <frame> <frame> </frameset>
　　【1】指定视窗的文件名称 -- src <frame src=HTML档名>
　　【2】定义视窗的名称 -- name
　　<frame name=视窗名称>
　　【3】设定文件与上下边框的距离 -- marginheight
　　<frame marginheight=点数>
　　【4】设定文件与左右边框的距离 -- marginwidth
　　<frame marginwidth=点数>
　　【5】设定分割视窗卷轴 -- scrolling
　　<frame scrolling=#> #号可为 yes：固定出现卷轴
　　no：不出现卷轴
　　auto：自动判断文件大小需不需要卷轴（预设值）
　　【6】锁住分割视窗的大小 -- noresize <frame noresize>
　　六、歌曲代码:
　　在这组代码中，不必管它是mms.http.rtsp，只要看尾缀是asf、wma、wmv、wmv、rm都可适用下面的代码:
　　1. 手动播放:
　　<EMBED src=歌曲地址 volume="100" width=39 height=18 hidden="FALSE" autostart="fault" type="audio/x-pn-realaudio-plugin" controls="PlayButton">
　　2. 打开页面自动播放:
　　<EMBED src="歌曲地址" width="39" height="18" autostart="true" hidden="false" loop="infinite" align="middle" volume="100" type="audio/x-pn-realaudio-plugin" controls="PlayButton" autostart="true">
　　------------------------------------------------------------------
　　套用代码:
　　<div align="center">
　　<table border="1" width="90%" height="403" background="背景图片地址">
　　<tr><td width="80%" height="100%">
　　<p align="center"><br><br><br>
　　<font face="华文彩云" size="6" color="#FFFFFF">歌曲或音乐名称</font><br><br>
　　<p align="center"><img src="图片地址"><br><br>
　　<font color="#FFFFFF" size=3>介绍文字</font><br><br><br>
　　<EMBED style="FILTER: xray()" src=音乐地址 width=250 height=30 type=audio/x-ms-wma autostart="true" loop="-1"><br><br><br>
　　</td></tr>
　　</table>
　　</div>
　　简易套用代码详解:
　　<div align="center">是定义帖子居中;
　　<table border="1" width="90%" height="403" background="背景图片地址"><tr><td width="80%" height="100%">
　　这其中的border="1"是定义表格边线的宽度,定义为0则无边线;width="90%" height="403"分别定义背景图表格的宽度和高度.如果背景图是一张大图,可以这样定义:width=图片宽度 height=图片高度
　　<p align="center"><br><br><br><font face="华文彩云" size="6" color="#FFFFFF">歌曲或音乐名称</font><br><br>
　　<p align="center">是定义文字居中的，<br>是回行代码，加几个就会空几行。<font face="华文彩云" size="6" color="#FFFFFF">是定义文字属性的。face="华文彩云"是定义字体，你可以把字体换成隶书、宋体等。size="6"是定义字号的，数字越大字越大，如果不定义，默认是2号字。color="#FFFFFF"是定义字体颜色的。全部字体颜色的代码在妙手饰图区有人发过，你可以找来改。
　　<p align="center"><img src="图片地址"><br><br><font color="#FFFFFF">介绍文字</font><br><br><br>
　　第一个括号里的代码仍然是定义图片和文字居中的。<img src="图片地址">是插入图片代码。<font color="#FFFFFF" size=3>介绍文字</font>是定义这段文字的。如果想改变字拧⒆痔濉⒆值难丈??烧瞻嵘厦嫖医驳亩ㄒ宸椒ā?/font>
　　<EMBED style="FILTER: xray()" src=音乐地址 width=250 height=30 type=audio/x-ms-wma autostart="true" loop="-1">
　　这一段是插入播放器代码，因为我插的是特殊的播放器，style="FILTER: xray()" 是特殊代码。“src=音乐地址”是插入音乐文件的地址。width=250 height=30分别定义播放器的宽度和高度(如果把宽和高都设成零则为隐藏,并且只能自动播放)。autostart="true" loop="-1"是定义音乐播放方式的，autostart="true"是设定手动或自动播放，“true”或“1”是自动播放，“false”或“0”是手动播放；loop="-1"是播放次数，“true”或“1”表示重复播放，“false”“-1”或“0”是只播放一次。
　　<br><br><br></td></tr></table></div>回行代码和与前面对应的固定代码。
　　<EMBED style="FILTER: xray()" src=音乐地址 width=250 height=30 type=audio/x-ms-wma autostart="true" loop="-1">
　　
这一段是插入播放器代码，因为我插的是特殊的播放器，style="FILTER: xray()" 是特殊代码。“src=音乐地址”是插入音乐文件的地址。width=250 height=30分别定义播放器的宽度和高度(如果把宽和高都设成零则为隐藏,并且只能自动播放)。autostart="true" loop="-1"是定义音乐播放方式的，autostart="true"是设定手动或自动播放，“true”或“1”是自动播放，“false”或“0”是手动播放；loop="-1"是播放次数，“true”或“1”表示重复播放，“false”“-1”或“0”是只播放一次。
　　<br><br><br></td></tr></table></div>回行代码和与前面对应的固定代码
```

