git pull;
git add .;
var=`date "+%Y-%m-%d_%H:%M:%S"`
# echo $var
git commit -m $var;
git push origin master
