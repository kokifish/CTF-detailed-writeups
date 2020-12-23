

# s34hunka

> 2020 12 23 https://huaweictf.xctf.org.cn/

题目描述：在excel中画画

>  相关文件: s34hunka.xlsx

表格形式：每个cell被填充了颜色，呈现出一张图

提取图片：

```python
import openpyxl
import xlrd
import numpy as np


# wb = openpyxl.load_workbook("s34hunka.xlsx")
# sheet = wb.active
# sheet.cell(1, 1).font.color.rgb  # 获取 表格内字体颜色
# temp = sheet.cell(1, 1).fill.fgColor.rgb
# print(temp, type(temp))  # 获取表格 填充色 颜色

def hex_to_rgb(value):
    value = value.lstrip('#')
    lv = len(value)
    return tuple(int(value[i:i + lv // 3], 16) for i in range(0, lv, lv // 3))


def main(sheet_img):
    rows_l = list(sheet_img.rows)
    print(rows_l[0][0], rows_l[0][-1], len(rows_l[0]), type(
        rows_l[0]), " len(rows_l)=", len(rows_l))
    print(rows_l[-1][0], rows_l[-1][-1], len(rows_l[-1]), type(rows_l[-1]))
    test_cell = list(sheet_img.rows)[0][0]  # 170B0D rgb(23, 11, 13)
    print(test_cell.fill.fgColor.rgb, type(test_cell.fill.fgColor.rgb))

    arr = np.zeros((len(rows_l), len(rows_l[0]), 3), dtype=np.int8)  # H*W*3
    for row in range(0, len(rows_l)):
        # print("row no: " + str(x))
        for col in range(0, len(rows_l[row])):
            rgb_value = rows_l[row][col].fill.fgColor.rgb
            # print(hex_to_rgb(rgb_value[2:]), end=" ")
            hex_value = hex_to_rgb(rgb_value[2:])
            arr[row][col][0] = hex_value[0]
            arr[row][col][1] = hex_value[1]
            arr[row][col][2] = hex_value[2]
    print(arr, arr.shape)
    print(ord('S')-ord('A'), arr[33][ord('S')-ord('A')])  # 50 34 37


if __name__ == "__main__":
    wb = openpyxl.load_workbook("s34hunka.xlsx")
    sheet_img = wb["img"]
    main(sheet_img)

```

