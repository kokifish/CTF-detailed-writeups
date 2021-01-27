git pull origin main;
git checkout main;
# git merge master
git add .;

git merge --no-ff -m "merge with no-ff" main

var=`date "+%Y-%m-%d_%H:%M:%S"`
# echo $var
git commit -m $var;
git push origin main

<<<<<<< HEAD

# 啥玩意儿 测试一下
=======
# TEST!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!!
>>>>>>> 8f5b5287bac47e75711454ef7f62300d41e6fbb2
