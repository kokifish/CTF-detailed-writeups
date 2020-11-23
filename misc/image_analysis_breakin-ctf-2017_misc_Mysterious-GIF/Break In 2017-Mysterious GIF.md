# Break In 2017-Mysterious GIF

> Question.gif



## extract a zip

- binwalk结果：

```python
$ binwalk Question.gif # analyzed with binwalk
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             GIF image data, version "89a", 440 x 608
2670386       0x28BF32        Zip archive data, at least v1.0 to extract, compressed size: 112890, uncompressed size: 112890, name: temp.zip
2783320       0x2A7858        End of Zip archive, footer length: 22
2783420       0x2A78BC        End of Zip archive, footer length: 22
```

- 在GIF文件后面，还有一些额外的zip文件，用`stat Question.gif`可以看到文件大小为2783442bytes
- 所以，如果提取文件的2670386 \~ 2783442 字节，共113056bytes，可以获得一个zip文件
- 使用`dd`指令切分文件，`if`=输入文件，`of`=输出文件，`skip`=跳过的block数量，`bs`=block size

```python
$ dd if=Question.gif of=temp.zip skip=2670386 bs=1 # 跳过前2670386字节
113056+0 records in
113056+0 records out
113056 bytes (113 kB, 110 KiB) copied, 0.196555 s, 575 kB/s # 输出结果表示，输出了113056 bytes
```

- 上述指令输出的结果为temp.zip

## zip analysis

```python
$ binwalk temp.zip
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v1.0 to extract, compressed size: 112890, uncompressed size: 112890, name: temp.zip
112934        0x1B926         End of Zip archive, footer length: 22
113034        0x1B98A         End of Zip archive, footer length: 22
```

- 输出看起来是只有一个temp.zip文件
- 由于zip开头为`PK..` (`0x04034b50`, `\x50\x4b\x03\x04`，注意字节序)

```console
$ hexdump -C temp.zip # 可以用这个指令看看文件的内容为什么
00000000  50 4b 03 04 0a 00 00 00  00 00 72 77 39 4a 7a a4  |PK........rw9Jz.|
00000010  10 56 fa b8 01 00 fa b8  01 00 08 00 1c 00 74 65  |.V............te|
00000020  6d 70 2e 7a 69 70 55 54  09 00 03 ff 6f 88 58 ff  |mp.zipUT....o.X.|
00000030  6f 88 58 75 78 0b 00 01  04 e8 03 00 00 04 e8 03  |o.Xux...........|
00000040  00 00 50 4b 03 04 0a 00  00 00 00 00 72 77 39 4a  |..PK........rw9J|
00000050  08 ca ac 67 00 01 00 00  00 01 00 00 0a 00 1c 00  |...g............|
00000060  70 61 72 74 61 61 2e 65  6e 63 55 54 09 00 03 ff  |partaa.encUT....|
00000070  6f 88 58 ff 6f 88 58 75  78 0b 00 01 04 e8 03 00  |o.X.o.Xux.......|
................................
```

- 由上面的输出观察可以看到，文件中可能包含多个zip文件，所以搜索zip文件开头的标志"\x50\x4b\x03\x04"

```python
$ binwalk -R "\x50\x4b\x03\x04" temp.zip # 搜索字符串包括转义的八进制和/或十六进制值
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Raw signature (\x50\x4b\x03\x04)
66            0x42            Raw signature (\x50\x4b\x03\x04)
492           0x1EC           Raw signature (\x50\x4b\x03\x04)
918           0x396           Raw signature (\x50\x4b\x03\x04)
1344          0x540           Raw signature (\x50\x4b\x03\x04)
....................................................................
112104        0x1B5E8         Raw signature (\x50\x4b\x03\x04)
112530        0x1B792         Raw signature (\x50\x4b\x03\x04)
```

- 由输出可以看到，除了头两个DECIMAL输出的差值为66以外，其他都为426bytes
- 猜测可能由于前面的66字节，导致`binwalk`无法识别出后面的zip文件

```python
$ dd if=temp.zip of=temp2.zip skip=66 bs=1 # 在temp.zip的基础上，去掉前66字节，保存为temp2.zip
$ binwallk temp2.zip
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v1.0 to extract, compressed size: 256, uncompressed size: 256, name: partaa.enc
404           0x194           End of Zip archive, footer length: 22
426           0x1AA           Zip archive data, at least v1.0 to extract, compressed size: 256, uncompressed size: 256, name: partab.enc
830           0x33E           End of Zip archive, footer length: 22
852           0x354           Zip archive data, at least v1.0 to extract, compressed size: 256, uncompressed size: 256, name: partac.enc
1256          0x4E8           End of Zip archive, footer length: 22
.............................................
111612        0x1B3FC         Zip archive data, at least v1.0 to extract, compressed size: 256, uncompressed size: 256, name: partkc.enc
112016        0x1B590         End of Zip archive, footer length: 22
112038        0x1B5A6         Zip archive data, at least v1.0 to extract, compressed size: 256, uncompressed size: 256, name: partkd.enc
112442        0x1B73A         End of Zip archive, footer length: 22
112464        0x1B750         Zip archive data, at least v1.0 to extract, compressed size: 256, uncompressed size: 256, name: partke.enc
112868        0x1B8E4         End of Zip archive, footer length: 22
112968        0x1B948         End of Zip archive, footer length: 22
```

- 注意这里结尾多了一个zip结尾，是前面那个的被去掉的zip头

## extract zips

```python
$ binwalk -e temp2.zip # 提取找到的任何文件 # 运行前可能需要dnf install java-devel
DECIMAL       HEXADECIMAL     DESCRIPTION
--------------------------------------------------------------------------------
0             0x0             Zip archive data, at least v1.0 to extract, compressed size: 256, uncompressed size: 256, name: partaa.enc
404           0x194           End of Zip archive, footer length: 22
426           0x1AA           Zip archive data, at least v1.0 to extract, compressed size: 256, uncompressed size: 256, name: partab.enc
830           0x33E           End of Zip archive, footer length: 22
..........................................................
```

- 然后可以在`_temp2.zip.extracted`文件夹中找到总共265个`partxx.enc`文件(每个文件都为256字节，可以猜测是被加密的)

```python
$ hexdump -C ./_temp2.zip.extracted/partab.enc # 256字节
00000000  26 ae c1 50 a3 a1 5d 32  6c f4 52 cb ca 63 78 c4  |&..P..]2l.R..cx.|
00000010  14 4f 1c 41 3a 26 cb 94  68 ff 67 1f 8c 84 d6 51  |.O.A:&..h.g....Q|
00000020  90 ae 62 19 24 33 c9 23  21 82 a7 9d b2 53 f1 4c  |..b.$3.#!....S.L|
00000030  67 b0 94 c6 d3 5c b6 63  3f fc f1 ea 9b 35 a1 70  |g....\.c?....5.p|
00000040  08 6e 53 00 14 ab 51 20  cc 9d e7 7f 54 37 11 8b  |.nS...Q ....T7..|
00000050  92 f6 51 e4 42 13 9e 7b  6e 58 c8 2a ae 75 04 3c  |..Q.B..{nX.*.u.<|
00000060  a2 95 62 d5 e2 48 9f 2f  29 11 d5 d2 51 02 fd 3a  |..b..H./)...Q..:|
00000070  c0 04 f4 25 d7 33 01 4b  9e cc c1 9b 3a 43 d1 e5  |...%.3.K....:C..|
00000080  65 2e 3d a5 2c 9a 07 d9  9f a3 e2 59 46 32 53 6b  |e.=.,......YF2Sk|
00000090  82 53 eb 67 14 e6 96 27  bd ad 84 1f 34 2d 31 71  |.S.g...'....4-1q|
000000a0  cd ae 17 a6 c0 f8 cc 23  16 7f af 80 40 f9 d8 2b  |.......#....@..+|
000000b0  0c 46 f0 79 d3 fa 9c 60  37 1f e6 f4 cc fd d9 b7  |.F.y...`7.......|
000000c0  66 21 8e 57 56 e4 76 fb  29 9d cc 7f 6b 7c 55 47  |f!.WV.v.)...k|UG|
000000d0  ff e1 17 33 ef b3 62 f6  b7 6a 5b 2f 52 de 8c a7  |...3..b..j[/R...|
000000e0  1d b6 a5 ac ac d8 07 9c  cd b4 83 e2 f4 94 7f 1d  |................|
000000f0  fb 43 80 a3 ab 74 f6 2a  a0 5b 0d f4 7d 9a 15 d4  |.C...t.*.[..}...|
00000100
```

- 至此，找寻需要进行解密的加密文件步骤完成，接下来找密钥

## find private key/gif analysis

> `identify a.gif` 获取一个或多个图像文件的格式和特性

```python
$ identify -verbose Question.gif
Image:
  Filename: Question.gif
  Format: GIF (CompuServe graphics interchange format)
  Mime type: image/gif
  Class: PseudoClass
  Geometry: 440x608+0+0
  Units: Undefined
  Colorspace: sRGB
  Type: Grayscale
  Base type: Undefined
  Endianness: Undefined
  Depth: 8-bit
................................
Scene: 0 of 26
  Compression: LZW
  Orientation: Undefined
  Properties:
    comment: 4d494945767749424144414e42676b71686b6947397730424151454641415343424b6b776767536c41674541416f4942415144644d4e624c3571565769435172
    date:create: 2020-11-21T11:40:12+00:00
    date:modify: 2020-11-21T11:40:12+00:00
    signature: 56b706869f46d9c871dc79ab22ae7fe17cf3daf6ed4d18988be582ae93824545
  Artifacts:
    filename: Question.gif
    verbose: true
  Tainted: False
  Filesize: 0B

```

- 虽然不知道其他属性一般应该是什么值，但是可以发现`comment`字段有意义不明的字符串

```python
$ identify -verbose Question.gif | grep comment
    comment: 4d494945767749424144414e42676b71686b6947397730424151454641415343424b6b776767536c41674541416f4942415144644d4e624c3571565769435172
    comment: 5832773639712f377933536849507565707478664177525162524f72653330633655772f6f4b3877655a547834346d30414c6f75685634364b63514a6b687271
    comment: 67384f79337335593546563177434b3736367532574c775672574d49554a47316a4444725276595049635135557143703545445143696f524d4763555a456732
    comment: 75766c3134324c44424161654f4c7a464d3465324a637a532b307238356d5052724353786a4c4b4c614c774949516e5a58497058535552562f776a6877575231
    comment: 664a474738512b7563454170615873634e435546343462506d344850434a2f306d7244435457482f59324350564a6b4e6b2b6f305637564f74484b734d4c344e
    comment: 434e414a483434572f4952774a6e744e572b4e3848726770526b467567686d4e6a63776c456b7274554b4731735243792f2f57687544756e5632706853525176
    comment: 486f74425a76796441674d424141454367674542414a79614e336d6c6b756e772b617137704b5561677636437a6442477964394a78447941706b314b374f4938
    comment: 54426873464d2f33744246654131592f41762b7568434c727967726b4279652f6963372f2b30356f3853392b65674d6b52584e484b41757952336752696b7759
    comment: 7678454b634a676a5a5a4c524656794159372f6c477634774e42683362495044664631446739737a596e6b774948396c4c454679656d4d3734416941596c6371
    comment: 6456645a49452f6271325a344a4f307439484367485a4e6651374a645266656a4e4a51565955443031517535644d744f523465494d6462576b68625658773254
    comment: 45304837785178746a7754367a557270714576764f376533464845734249583635565258524c6276394f6f61794a786352715838654a6b5269344c2f597a6f34
    comment: 4b5470456d6b64754a4c58734677743361715154626a5a48584f6c5454344e45647348327030547343414543675945412f653162737a4f3061312b6342614451
    comment: 6a514f2b50763942734a464442336f314c477555484d4e53384644706e334a3436556b59796b353276496130763454636a715353484e4976585730544445556b
    comment: 624e4641314870557856786c7730426965656838426733486658795142685876645444376b306c73446d4d456f3455504b59533644356359577972776864356e
    comment: 4344304c72786562674f373552784c35514549452b34435649516b4367594541337638522f584b52564a50453461456567377051347554766346786a454e4e65
    comment: 787866364b34787059344c6639636c49766465635268433274314864522b7853756c552f52536152727a4863773378672b4c31754f3073317435533766336e75
    comment: 3361696849586b636747537158435a3156487a426d65433430545673664179627337714a30785936543571384d6e78324f62355a336c49477579686a65566174
    comment: 4649493253647a324a2f55436759454174654131357a516f6a53504e482b62676d62424e717465763247556a536f374932556b777243316e4559515334636266
    comment: 5064444364643066684d6444585534766e2b66575539686b58706d4b7043592b416363626c56554e744e4d4b6649423453484d78716a426961386f31616e5a35
    comment: 726b6e6f5638576d4a4f50645a6259666478422f4b4432454434444243464756494c79417975657731506657436f64586969502f5a356a67742b6b4367594541
    comment: 727378716f61306f316f3975695237752b48735835494e6f5854394f4f475933715144576a55526e61435779774d756a525979355a774b363930416f6f4c5253
    comment: 744e555633334b3453416868384b7153714f6830652b34636b5762354170666c38634b3561362b76383854303958384141645935504247335465622b7673357a
    comment: 54704d75626c54434b4a773259617a4754385579564e38666635334e4f3951426f4533686d45796f642f4543675941396b307879434a7a6376654b6478727936
    comment: 706a51786b39465a7a3341744570316f635635566f776167562b4f4e657a2f4863634638474a4f384244716c5036586b634c5574736e70367459526545494349
    comment: 484b7735432b667741586c4649746d30396145565458772b787a4c4a623253723667415450574d35715661756278667362356d58482f77443969434c684a536f
    comment: 724b3052485a6b745062457335797444737142486435504646773d3d
```

- 疑似为16进制表示的字符串，将以上内容解码(hex to string)，可以得到以下字符串，猜测以下字符串为RSA加密的私钥

```python
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDdMNbL5qVWiCQrX2w69q/7y3ShIPueptxfAwRQbROre30c6Uw/oK8weZTx44m0ALouhV46KcQJkhrqg8Oy3s5Y5FV1wCK766u2WLwVrWMIUJG1jDDrRvYPIcQ5UqCp5EDQCioRMGcUZEg2uvl142LDBAaeOLzFM4e2JczS+0r85mPRrCSxjLKLaLwIIQnZXIpXSURV/wjhwWR1fJGG8Q+ucEApaXscNCUF44bPm4HPCJ/0mrDCTWH/Y2CPVJkNk+o0V7VOtHKsML4NCNAJH44W/IRwJntNW+N8HrgpRkFughmNjcwlEkrtUKG1sRCy//WhuDunV2phSRQvHotBZvydAgMBAAECggEBAJyaN3mlkunw+aq7pKUagv6CzdBGyd9JxDyApk1K7OI8TBhsFM/3tBFeA1Y/Av+uhCLrygrkBye/ic7/+05o8S9+egMkRXNHKAuyR3gRikwYvxEKcJgjZZLRFVyAY7/lGv4wNBh3bIPDfF1Dg9szYnkwIH9lLEFyemM74AiAYlcqdVdZIE/bq2Z4JO0t9HCgHZNfQ7JdRfejNJQVYUD01Qu5dMtOR4eIMdbWkhbVXw2TE0H7xQxtjwT6zUrpqEvvO7e3FHEsBIX65VRXRLbv9OoayJxcRqX8eJkRi4L/Yzo4KTpEmkduJLXsFwt3aqQTbjZHXOlTT4NEdsH2p0TsCAECgYEA/e1bszO0a1+cBaDQjQO+Pv9BsJFDB3o1LGuUHMNS8FDpn3J46UkYyk52vIa0v4TcjqSSHNIvXW0TDEUkbNFA1HpUxVxlw0Bieeh8Bg3HfXyQBhXvdTD7k0lsDmMEo4UPKYS6D5cYWyrwhd5nCD0LrxebgO75RxL5QEIE+4CVIQkCgYEA3v8R/XKRVJPE4aEeg7pQ4uTvcFxjENNexxf6K4xpY4Lf9clIvdecRhC2t1HdR+xSulU/RSaRrzHcw3xg+L1uO0s1t5S7f3nu3aihIXkcgGSqXCZ1VHzBmeC40TVsfAybs7qJ0xY6T5q8Mnx2Ob5Z3lIGuyhjeVatFII2Sdz2J/UCgYEAteA15zQojSPNH+bgmbBNqtev2GUjSo7I2UkwrC1nEYQS4cbfPdDCdd0fhMdDXU4vn+fWU9hkXpmKpCY+AccblVUNtNMKfIB4SHMxqjBia8o1anZ5rknoV8WmJOPdZbYfdxB/KD2ED4DBCFGVILyAyuew1PfWCodXiiP/Z5jgt+kCgYEArsxqoa0o1o9uiR7u+HsX5INoXT9OOGY3qQDWjURnaCWywMujRYy5ZwK690AooLRStNUV33K4SAhh8KqSqOh0e+4ckWb5Apfl8cK5a6+v88T09X8AAdY5PBG3Teb+vs5zTpMublTCKJw2YazGT8UyVN8ff53NO9QBoE3hmEyod/ECgYA9k0xyCJzcveKdxry6pjQxk9FZz3AtEp1ocV5VowagV+ONez/HccF8GJO8BDqlP6XkcLUtsnp6tYReEICIHKw5C+fwAXlFItm09aEVTXw+xzLJb2Sr6gATPWM5qVaubxfsb5mXH/wD9iCLhJSorK0RHZktPbEs5ytDsqBHd5PFFw==
```

- 将得到的内容写入到文件

```python
$ echo MIIEvw ......... qBHd5PFFw== >> dec.pem # 将以上字符串写入到dec.pem文件中 #可用 cat dec.dec 确认
```

- 然后还需给文件的首行、末行添加一些信息（否则会openssl命令会报错），使得 `dec.pem` 内容为：

```python
-----BEGIN RSA PRIVATE KEY-----
MIIEvwIBADANBgkqhkiG9w0BAQEFAASCBKkwggSlAgEAAoIBAQDdMNbL5qVWiCQrX2w69q/7y3ShIPueptxfAwRQbROre30c6Uw/oK8weZTx44m0ALouhV46KcQJkhrqg8Oy3s5Y5FV1wCK766u2WLwVrWMIUJG1jDDrRvYPIcQ5UqCp5EDQCioRMGcUZEg2uvl142LDBAaeOLzFM4e2JczS+0r85mPRrCSxjLKLaLwIIQnZXIpXSURV/wjhwWR1fJGG8Q+ucEApaXscNCUF44bPm4HPCJ/0mrDCTWH/Y2CPVJkNk+o0V7VOtHKsML4NCNAJH44W/IRwJntNW+N8HrgpRkFughmNjcwlEkrtUKG1sRCy//WhuDunV2phSRQvHotBZvydAgMBAAECggEBAJyaN3mlkunw+aq7pKUagv6CzdBGyd9JxDyApk1K7OI8TBhsFM/3tBFeA1Y/Av+uhCLrygrkBye/ic7/+05o8S9+egMkRXNHKAuyR3gRikwYvxEKcJgjZZLRFVyAY7/lGv4wNBh3bIPDfF1Dg9szYnkwIH9lLEFyemM74AiAYlcqdVdZIE/bq2Z4JO0t9HCgHZNfQ7JdRfejNJQVYUD01Qu5dMtOR4eIMdbWkhbVXw2TE0H7xQxtjwT6zUrpqEvvO7e3FHEsBIX65VRXRLbv9OoayJxcRqX8eJkRi4L/Yzo4KTpEmkduJLXsFwt3aqQTbjZHXOlTT4NEdsH2p0TsCAECgYEA/e1bszO0a1+cBaDQjQO+Pv9BsJFDB3o1LGuUHMNS8FDpn3J46UkYyk52vIa0v4TcjqSSHNIvXW0TDEUkbNFA1HpUxVxlw0Bieeh8Bg3HfXyQBhXvdTD7k0lsDmMEo4UPKYS6D5cYWyrwhd5nCD0LrxebgO75RxL5QEIE+4CVIQkCgYEA3v8R/XKRVJPE4aEeg7pQ4uTvcFxjENNexxf6K4xpY4Lf9clIvdecRhC2t1HdR+xSulU/RSaRrzHcw3xg+L1uO0s1t5S7f3nu3aihIXkcgGSqXCZ1VHzBmeC40TVsfAybs7qJ0xY6T5q8Mnx2Ob5Z3lIGuyhjeVatFII2Sdz2J/UCgYEAteA15zQojSPNH+bgmbBNqtev2GUjSo7I2UkwrC1nEYQS4cbfPdDCdd0fhMdDXU4vn+fWU9hkXpmKpCY+AccblVUNtNMKfIB4SHMxqjBia8o1anZ5rknoV8WmJOPdZbYfdxB/KD2ED4DBCFGVILyAyuew1PfWCodXiiP/Z5jgt+kCgYEArsxqoa0o1o9uiR7u+HsX5INoXT9OOGY3qQDWjURnaCWywMujRYy5ZwK690AooLRStNUV33K4SAhh8KqSqOh0e+4ckWb5Apfl8cK5a6+v88T09X8AAdY5PBG3Teb+vs5zTpMublTCKJw2YazGT8UyVN8ff53NO9QBoE3hmEyod/ECgYA9k0xyCJzcveKdxry6pjQxk9FZz3AtEp1ocV5VowagV+ONez/HccF8GJO8BDqlP6XkcLUtsnp6tYReEICIHKw5C+fwAXlFItm09aEVTXw+xzLJb2Sr6gATPWM5qVaubxfsb5mXH/wD9iCLhJSorK0RHZktPbEs5ytDsqBHd5PFFw==
-----END RSA PRIVATE KEY-----
```



## decryption

- `openssl rsautl -decrypt -inkey dec.pem -in ./_temp2.zip.extracted/partaa.enc -out partaa.out `使用RSA私钥文件`dec.pem`对指定的文件进行解密，输出为`partaa.out`
- 使用python脚本对所有`partxx.enc`进行解密，注意这里将脚本、`dec.pem`和`partxx.enc`放在同一目录下，

```python
# Break In 2017-Mysterious GIF 重复执行解密指令
import os
import subprocess
import shlex

def exe_loop():
    str_sta = str("openssl rsautl -decrypt -inkey dec.pem -in part")
    str_mid = str(".enc -out part")
    # aa to ke
    num = 0
    for i in range(ord("a"), ord("z") + 1):
        for j in range(ord("a"), ord("z") + 1):
            cmd = str_sta + chr(i) + chr(j) + str_mid + chr(i) + chr(j)
            args = shlex.split(cmd)
            subprocess.Popen(args)
            num += 1
            if(num >= 265):
                return

if __name__ == "__main__":
    exe_loop()
```

- 将所有`partxx`连接成一个文件：`cat part?? > final`
- 如果`partxx.enc`和`partxx`在同一个目录下，那么不能用`cat partxx > final`，否则会把`partxx.enc`和`partxx`一起用来连接成`final`，`?`表示通配一个字符

## flag

```python
$ stat final
  File: final
  Size: 50833           Blocks: 104        IO Block: 4096   regular file
Device: fd00h/64768d    Inode: 3802324     Links: 1
Access: (0644/-rw-r--r--)  Uid: (    0/    root)   Gid: (    0/    root)
Context: unconfined_u:object_r:admin_home_t:s0
Access: 2020-11-23 15:09:35.524421669 +0800
Modify: 2020-11-23 15:09:51.806185140 +0800
Change: 2020-11-23 15:09:51.806185140 +0800
 Birth: 2020-11-23 15:07:46.185009954 +0800
$ file final
final: JPEG image data, JFIF standard 1.01, aspect ratio, density 1x1, segment length 16, baseline, precision 8, 440x608, components 3
$ feh final
```

- 图片`final`显示的内容就是flag了，fedora可以在命令行内使用`feh final`查看图片

flag: FelicityIsFun
