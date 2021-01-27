git pull origin main;
git checkout main;
# git merge master
git add .;

git merge --no-ff -m "merge with no-ff" main

var=`date "+%Y-%m-%d_%H:%M:%S"`
# echo $var
git commit -m $var;
git push origin main


# 啥玩意儿 测试一下