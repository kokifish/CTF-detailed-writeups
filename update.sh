
# merge local master to main
# git merge master;

git add . -v;
var=`date "+%Y-%m-%d_%H:%M:%S"`
# echo $var
git commit -am $var;

git pull origin main;


echo "[DEBUG] git merge ====================="
git merge -v --no-ff -m "merge with no-ff" main

git push -v origin main



# In Onedrive
