# zongheng-2020_misc_mosaic

> 2020 纵横杯 题目：misc-mosaic 
>
> 文件：mosaic.png

- 在Github上下载Depix脚本： https://github.com/beurtschipper/Depix
- 执行指令`python depix.py -p mosaic.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o output.png`
- 输出如下：

```python
python depix.py -p mosaic.png -s images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png -o output.png
INFO:root:Loading pixelated image from mosaic.png
INFO:root:Loading search image from images/searchimages/debruinseq_notepad_Windows10_closeAndSpaced.png
INFO:root:Finding color rectangles from pixelated space
INFO:root:Found 93 same color rectangles
INFO:root:91 rectangles left after moot filter
INFO:root:Found 2 different rectangle sizes
INFO:root:Finding matches in search image
INFO:root:Removing blocks with no matches
INFO:root:Splitting single matches and multiple matches
INFO:root:[16 straight matches | 72 multiple matches]
INFO:root:Trying geometrical matches on single-match squares
INFO:root:[16 straight matches | 72 multiple matches]
INFO:root:Trying another pass on geometrical matches
INFO:root:[16 straight matches | 72 multiple matches]
INFO:root:Writing single match results to output
INFO:root:Writing average results for multiple matches to output
INFO:root:Saving output image to: output.png
```

- 打开output.png可以读出图片内容为0123468abd68abd0123
- 补全至flag格式：flag{0123468abd68abd0123}