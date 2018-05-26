echo 'rm -rf build/'
rm -rf build/
echo 'cd src'
cd src
echo 'make clean'
make clean
echo 'make -j8'
make -j8
echo 'rm /home/rbharath/anaconda3/envs/hepy/lib/fhe.a'
rm /home/rbharath/anaconda3/envs/hepy/lib/fhe.a
echo 'cp fhe.a /home/rbharath/anaconda3/envs/hepy/lib/'
cp fhe.a /home/rbharath/anaconda3/envs/hepy/lib/
echo 'rm -rf /home/rbharath/anaconda3/envs/hepy/lib/python3.5/site-packages/hepy*'
rm -rf /home/rbharath/anaconda3/envs/hepy/lib/python3.5/site-packages/hepy*
echo 'cd ..'
cd ..
echo 'python setup.py install --force'
python setup.py install --force
