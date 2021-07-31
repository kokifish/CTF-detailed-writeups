if [ ! -n "$1" ];then
    echo "please give commit massge after bash. e.g. 
    > bash update.sh \"crypto: tctf xxx writeups\"
    > bash update.sh \"pwn: pwn.md heap UAF\""
    exit 1
fi
var=$1
# echo $var

echo "[Step-1] git pull origin main:"
git pull origin main -v;
echo
echo "=== [WARNING] If conflict occured, related files will show below: ========="
git status
echo "=== [WARNING] Fix by hands if conflict exits. Then [RE-RUN] this script ==="
echo 

echo "[Step-2] Local changes add and commit:"
git checkout main;
git add . -v;

git commit -am "$var";


echo "[Step-3] git push origin main:"
git push origin main