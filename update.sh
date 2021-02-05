echo "[Step-1] git pull origin main:"
git pull origin main;
echo 
echo "=== [WARNING] If conflict occured, related files will show below: ========="
git status
echo "=== [WARNING] Fix by hands if conflict exits. Then [RE-RUN] this script ==="
echo 

echo "[Step-2] Local changes add and commit:"
git checkout main;
git add . -v;
var=`date "+%Y-%m-%d_%H:%M:%S"`
# echo $var
git commit -am $var;


echo "[Step-3] git push origin main:"
git push origin main