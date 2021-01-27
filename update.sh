git checkout main -q;

git add . -v;
var=`date "+%Y-%m-%d_%H:%M:%S"`
# echo $var
git commit -am $var;

echo "[DEBUG] git pull origin main START ==="
git pull -v origin main;

echo 
echo "[WARNING] If conflict occured, related files will show below: ============="
git status
echo "[WARNING] Fix by hands if conflict exits. ================================"
echo 

echo "[DEBUG] git push ====================="
git push -v origin main