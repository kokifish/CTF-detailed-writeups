# git pull origin main;
git fetch origin main;
git checkout main;
# git merge master
git add .;
var=`date "+%Y-%m-%d_%H:%M:%S"`
# echo $var
git commit -m $var;
git push origin main


# 啥玩意儿 测试一下