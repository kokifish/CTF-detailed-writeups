'''
# p = 0x00f23799c031b942026e420769b74d22fa2114428189139c43c366c6ab8367c6b3d6f821449aafb2058b0e6ed964fa0ad45fb306f96376e80823a72b58101919e50acad3b5e6d079e7ff9218ed6df6edbef536742714ce88b2e717f45af53ef0d04c89faf01c80b28e764973aba27726c85c0236e8756a865c03577722bac5e391
# q = 0x00c9d24330fa4945cfe1e5d6912d6bde0231035a1cc8d8ae67d949347b895f8d579bce2adaf37c568957b17a6564dbf80d36d81e4622ab30e02132b0155aefbd3912a27c625a9b7b05bc72217039f5aa88c20cbf9871c3228e9d80d9106f94b11c1f50c40c96862b5cd6b6f781883dd2eff80a059d3ca027af6a03edeb34a7390f
# n = p*q
e = 3
n = 0x4ac5cbf84a2f9a1042c552c77075459d2273994453caea11fbf696b9a8d41937b48be43c71ec6c37470ba9d280a23301b817314a94c786962e4a98ddb260bf2d53a51a6f9c87258110fb2bc9fe8fa44a24e6f95fd5d098bd907d5f8565a0ed7c681cf5e6a79b28438077f6b8d3ae1edf4229102b4ebe29d1f37b9357d3ffff39
p = 0x80f7a73798f638d10180223d7b482035b69b51ffe09ad9e42602cc9d489837be7d1ac92e90b09837144c1220ed4ff0ea00000000000000000000000000000000
beta = 0.5
epsilon = beta^2/7
pbits = p.nbits()
kbits = floor(n.nbits()*(beta^2-epsilon))
pbar = p & (2^pbits-2^kbits)
print "upper %d bits (of %d bits) is given" % (pbits-kbits, pbits)
PR.<x> = PolynomialRing(Zmod(n))
f = x + pbar
print 'p_fake =',p
x0 = f.small_roots(X=2^kbits, beta=0.3)[0]  # find root < 2^kbits with factor >= n^0.3
print 'p =',x0 + pbar
'''


# next exp


n = 0x73cec712124b33c0294e01eb52e8c3cd2fe9ddbcbf457b3b950360063dfae42cbbe9855bd986bcfea0948fadfb252f5e2ff3c982ff47afb6596a496636f1fc5ecfe9f5db7620b23fe9e30d230aa9299ab9a78bfb5e0630fd1149259b2b2104ea65d2e27b89785e4bf01d0594d9f94575cbcc3383f63c5aabe4d5b48eb761cce3ab21689b3f3155b5f15efee240d5ac11cee2acbd019de7c06f607ea618b5cd735b5a6972d2b446a12ff58cf8314822fa5ea09d0963acd00441b2a1b37aca01d7f39052927db98a0bd5ca1c49a7ad67923e3aac30ecd33cc8b4b30a40cdb3acc721ee5da53a02977cee959affe672a668525eb78df96af0a14f4ac04fab68efa8eabe9535e1064a5fc2ff7cac9520210311db0c3bf91101bc55a67a81e4f69364c724ee6ad6bdc301df642c9392e9befa4ff0d65481adb6feac251cd207044587da9710809700246cb3c63e659a97249f5e7418568e37db2fb2c1115e719d6682bb2e89b4e23d40ba4c532f289e10e0b89a5647c486a09b9e376844171b229d74f871004d4945a702a391a04ac704f43809e972891e6ab33b3c0f03f0b6f9ae005b26be6e647a1865c727277423f59a595187ffbfea13501e23b6b57ef115eaa6febcb207a3112628652a39578847241c33989e84607b0f683b30ddf773348b07360b063d9120a397809591ca18a04cd32ad9cbfe0494ed3ae8d2c5b43fdb51cb
p_fake = 25469341510015610710601677541490068882874022771473379147959682877979811860690835905177575433486769235926750944378553837429714908846121392087707617153368450157831411033840331452402635316893579428297241392591768100008774205252294780519995317089863801331600746389471563346749402400584048767782402832414560955794979239140648096754408560344380360521300295416056532504527346890878830708030202503589314586128121926254376071861981570648841288044240102936057199541504839050994656267226010545841307490110261343492485615893311098351703701000220286503350522201318815497988460167971677642567134161349144833221240627311534482202273
pbits = p_fake.nbits()
kbits = 900
#kbits = 200
pbar = p_fake & (2^pbits-2^kbits)
print("upper %d bits (of %d bits) is given" % (pbits-kbits, pbits))
PR.<x> = PolynomialRing(Zmod(n))
f = x + pbar
x0 = f.small_roots(X=2^kbits, beta=0.4)[0]  # find root < 2^kbits with factor >= n^0.3
p= x0 + pbar
print('p =',p)